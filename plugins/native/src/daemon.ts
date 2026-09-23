import { publicReason, scanNotice } from '../../deepseek/src/notice.ts'
import { unavailableScanReference } from '../../deepseek/src/references.ts'
import { execFile } from 'node:child_process'
import { randomUUID, timingSafeEqual } from 'node:crypto'
import { constants } from 'node:fs'
import { chmod, link, lstat, open, readFile, unlink } from 'node:fs/promises'
import { createServer, type Socket } from 'node:net'
import { isAbsolute, join, relative, sep } from 'node:path'
import { promisify } from 'node:util'
import { patronusRoot } from '../../deepseek/src/settings.ts'
import type { JsonValue } from './types.ts'
import { executablePath } from '../../deepseek/src/client.ts'
import { SessionState, type SessionRuntime } from '../../deepseek/src/sessions.ts'
import { StaticScanner } from '../../deepseek/src/static.ts'
import { waitForScan } from '../../deepseek/src/wait.ts'
import { autoRedact } from '../../deepseek/src/auto-redaction.ts'
import { brokerFailure, CALL_TIMEOUT, prepareBroker, privateDirectory, readFrame, readPrivate, record, unavailable, validRequest, writeFrame, type BrokerConfig, type BrokerRequest } from './broker.ts'

const IDLE_MS = 30 * 60_000 // Greater than the maximum five-minute runtime scan deadline.
const run = promisify(execFile)

interface Owner { pid: number; started: string }

/** A PID alone can be recycled while a stale lock remains. */
export async function processIdentity(pid: number): Promise<string | undefined> {
  if (!Number.isSafeInteger(pid) || pid < 1) return undefined
  try {
    if (process.platform === 'linux') {
      const stat = await readFile(`/proc/${pid}/stat`, 'utf8')
      const fields = stat.slice(stat.lastIndexOf(')') + 1).trim().split(/\s+/)
      const started = fields[19] // proc_pid_stat(5), field 22 after pid/comm.
      return /^\d+$/.test(started ?? '') ? `linux:${started}` : undefined
    }
    if (process.platform === 'darwin') {
      const result = await run('/bin/ps', ['-p', String(pid), '-o', 'lstart='], {
        encoding: 'utf8', maxBuffer: 1024, shell: false, timeout: 2000,
      })
      const started = result.stdout.trim()
      return started && started.length <= 64 ? `darwin:${started}` : undefined
    }
  } catch { /* Missing/dead process. */ }
  return undefined
}

async function owner(path: string): Promise<Owner> {
  // Publication briefly leaves both the staging name and owner name linked.
  const value: unknown = JSON.parse(await readPrivate(path, 128, 2))
  if (!record(value) || !Number.isSafeInteger(value.pid) || (value.pid as number) < 1 ||
      typeof value.started !== 'string' || value.started.length < 1 || value.started.length > 80 ||
      Object.keys(value).some(key => !['pid', 'started'].includes(key))) throw brokerFailure()
  return { pid: value.pid as number, started: value.started }
}

async function ownedByLiveProcess(path: string): Promise<boolean> {
  const value = await owner(path)
  return await processIdentity(value.pid) === value.started
}

/** Publish a complete owner record exclusively. Death before link() leaves only
 * an unreferenced staging file; death afterwards leaves a readable owner PID. */
async function publishOwner(path: string): Promise<void> {
  const started = await processIdentity(process.pid)
  if (!started) throw brokerFailure()
  const staged = `${path}.owner-${process.pid}-${randomUUID()}`
  const file = await open(staged, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try {
    await file.writeFile(JSON.stringify({ pid: process.pid, started }))
    await file.sync()
    await link(staged, path)
  } finally { await file.close(); await unlink(staged).catch(() => {}) }
}

/** A separate owner record serializes stale-owner recovery. It uses the same
 * recovery protocol, so a process killed while recovering cannot strand it.
 * The depth bound fails closed on an unexpectedly long or hostile lock chain. */
async function acquire(path: string, socketPath?: string, depth = 0): Promise<boolean> {
  if (depth > 16) throw brokerFailure()
  const create = async () => {
    await publishOwner(path)
  }
  try { await create(); return true }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw brokerFailure() }
  if (await ownedByLiveProcess(path)) return false
  const reapPath = `${path}.reap`
  if (!await acquire(reapPath, undefined, depth + 1)) return false
  try {
    if (await ownedByLiveProcess(path)) return false
    if (socketPath) {
      try {
        const info = await lstat(socketPath)
        if (!info.isSocket() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0) throw brokerFailure()
        await unlink(socketPath)
      } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw brokerFailure() }
    }
    await unlink(path)
    try { await create(); return true }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'EEXIST') return false; throw brokerFailure() }
  } finally { if ((await owner(reapPath)).pid === process.pid) await unlink(reapPath) }
}

function toml(value: unknown): string {
  if (typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)) return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(toml).join(', ')}]`
  if (record(value)) return `{${Object.entries(value).map(([key, item]) => `${JSON.stringify(key)}=${toml(item)}`).join(',')}}`
  throw brokerFailure()
}

/** Enforce provider/download policy before LocalClient can initialize any assets. */
async function frozenConfig(prepared: Awaited<ReturnType<typeof prepareBroker>>, signal: AbortSignal): Promise<{ executable: string; configPath: string; provider: string }> {
  const { config, directory, repository } = prepared
  const { realpath } = await import('node:fs/promises')
  const executable = await realpath(executablePath(config.executable))
  const within = relative(repository, executable)
  if (within === '' || (within !== '..' && !within.startsWith(`..${sep}`) && !isAbsolute(within))) throw brokerFailure()
  let configPath = config.configPath
  if (configPath === undefined) {
    const candidate = join(patronusRoot(), 'config.toml')
    try { await lstat(candidate); configPath = candidate }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw brokerFailure() }
  }
  const args = ['config', 'print', '--format', 'json', ...(configPath ? ['--config', configPath] : [])]
  const printed = await run(executable, args, { cwd: config.cwd, signal, timeout: 10_000, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024, encoding: 'utf8', shell: false })
  const value: unknown = JSON.parse(printed.stdout)
  if (!record(value) || value.schema_version !== 1 || !record(value.provider) || !['local', 'api', 'hybrid'].includes(String(value.provider.mode)) ||
      !record(value.ark) || value.ark.download_files !== false) throw brokerFailure()
  for (const key of ['scan', 'ignore', 'chunking', 'output', 'progress', 'support', 'runtime']) if (!record(value[key])) throw brokerFailure()
  value.output = { ...value.output as object, include_chunk_content: false, include_evidence_text: false, write_progress_events: false }
  configPath = join(directory, `broker-config-${process.pid}.toml`)
  const file = await open(configPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try { await file.writeFile(Object.entries(value).map(([key, item]) => `${JSON.stringify(key)}=${toml(item)}`).join('\n')); await file.sync() }
  finally { await file.close() }
  return { executable, configPath, provider: String(value.provider.mode) }
}

const count = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0
/** Keep protocol metadata; arbitrary backend fields and diagnostic strings never escape. */
function scanResult(value: unknown, allowOriginal: boolean): JsonValue {
  if (!record(value) || typeof value.status !== 'string' || !['pending', 'approved', 'dangerous', 'failed', 'incomplete', 'cancelled', 'expired', 'unavailable'].includes(value.status) ||
      typeof value.scan_id !== 'string' || !/^[a-f0-9]{32}$/.test(value.scan_id)) return unavailable()
  const result: Record<string, JsonValue> = { scan_id: value.scan_id, status: value.status }
  if (record(value.coverage)) {
    const coverage: Record<string, JsonValue> = {}
    if (typeof value.coverage.complete !== 'boolean') return unavailable()
    coverage.complete = value.coverage.complete
    for (const key of ['fields_total', 'fields_scanned', 'bytes_total', 'bytes_scanned']) {
      if (!count(value.coverage[key])) return unavailable()
      coverage[key] = value.coverage[key]
    }
    result.coverage = coverage
  }
  if (value.status === 'approved' && (!record(value.coverage) || value.coverage.complete !== true ||
      value.coverage.fields_total !== value.coverage.fields_scanned || value.coverage.bytes_total !== value.coverage.bytes_scanned)) return unavailable()
  if (Array.isArray(value.findings)) {
    const findings: JsonValue[] = []
    for (const item of value.findings.slice(0, 100)) {
      if (!record(item) || typeof item.category !== 'string' || !['prompt_injection', 'injection', 'dlp', 'pii', 'threat'].includes(item.category)) return unavailable()
      const finding: Record<string, JsonValue> = { category: item.category }
      if (item.level !== undefined) { if (typeof item.level !== 'string' || !['l1', 'l2', 'l3'].includes(item.level)) return unavailable(); finding.level = item.level }
      if (typeof item.confidence === 'number' && Number.isFinite(item.confidence) && item.confidence >= 0 && item.confidence <= 1) finding.confidence = item.confidence
      for (const key of ['start_byte', 'end_byte', 'field_id']) if (count(item[key])) finding[key] = item[key]
      findings.push(finding)
    }
    result.findings = findings
  }
  if (typeof value.job_status === 'string' && ['queued', 'running', 'scanning', 'completed', 'failed', 'cancelled', 'expired'].includes(value.job_status)) result.job_status = value.job_status
  if (typeof value.cached === 'boolean') result.cached = value.cached
  if (typeof value.redacted_available === 'boolean') result.redacted_available = value.redacted_available
  if (allowOriginal && value.status === 'approved' && Object.hasOwn(value, 'result')) result.result = value.result as JsonValue
  const notice = scanNotice(value.notice)
  if (notice) result.notice = notice as unknown as JsonValue
  const reason = publicReason(value.reason)
  if (reason) result.reason = reason
  return result
}

/** Dedicated per-host/session process. The CLI dispatches this only in daemon mode. */
export async function serveBroker(input: BrokerConfig): Promise<void> {
  let prepared: Awaited<ReturnType<typeof prepareBroker>>
  try { prepared = await prepareBroker(input) } catch { return }
  const { config, id, directory, capability, socketPath, socketRoot, key, digest, sessions } = prepared
  const lockPath = join(socketRoot, `${key}.lock`)
  try { if (!await acquire(lockPath, socketPath)) return } catch { return }
  const shutdown = new AbortController()
  const sockets = new Set<Socket>()
  let runtime: Promise<SessionRuntime> | undefined
  let runtimeSessions: SessionState | undefined
  let scanner: StaticScanner | undefined
  let snapshot: string | undefined
  let closing = false
  let idle: ReturnType<typeof setTimeout> | undefined
  const boot = (): Promise<SessionRuntime> => {
    sessions.assertUsable(id)
    runtime ??= (async () => {
      const frozen = await frozenConfig(prepared, shutdown.signal)
      snapshot = frozen.configPath
      await privateDirectory(join(directory, 'scanner'))
      runtimeSessions = new SessionState({ ...frozen, stateDir: config.stateDir })
      const connected = await runtimeSessions.runtime(id, shutdown.signal)
      if (connected.hello.ark_version !== '0.1.7' || connected.hello.provider !== frozen.provider) { await runtimeSessions.close(); throw brokerFailure() }
      return connected
    })()
    return runtime
  }
  const dispatch = async (request: BrokerRequest, signal: AbortSignal): Promise<JsonValue> => {
    if (request.method === 'close') return { closed: true }
    sessions.assertUsable(id)
    // Static audits own their CLI lifecycle and configuration validation. Do not
    // require an unrelated runtime worker/model startup just to audit a file.
    if (request.method === 'static') {
      scanner ??= new StaticScanner({ executable: config.executable, configPath: config.configPath }, shutdown.signal, 300_000, true)
      const result = await scanner.scan({ kind: request.kind, path: request.path, ...(request.server === undefined ? {} : {server:request.server}) }, signal)
      return record(result) && result.schema === 'patronus.deepseek.static.v1'
        ? { ...result, schema: 'patronus.static.v1' }
        : result
    }
    if (request.method === 'read_static_redacted') {
      return scanner?.readRedacted(request.fileId, signal) ?? {
        status: 'invalid_reference', code: 'scan_not_available', expected: 'static_file_id',
        message: 'Use a file_id returned by a static finding in this session.',
      }
    }
    const { client, hello } = await boot()
    if (signal.aborted) return unavailable()
    const session = sessions.capability(id)
    if (request.method === 'check') {
      const value = await client.check({ session, scan_id: request.scanId }, signal)
      const visible = await autoRedact(value, () => client.readRedacted({ session, scan_id: request.scanId }, signal))
      if (visible.status === 'redacted') return { ...scanResult(value, false) as object, status: 'redacted', result: visible.result! }
      return value.status === 'unavailable' ? unavailableScanReference() : scanResult(value, true)
    }
    if (request.method === 'read_redacted') {
      const value = await client.readRedacted({ session, scan_id: request.scanId }, signal)
      return value.status === 'redacted' && value.result !== undefined ? { scan_id: request.scanId, status: 'redacted', result: value.result } : unavailableScanReference()
    }
    if (request.method !== 'request' && request.method !== 'response') throw brokerFailure()
    if (Buffer.byteLength(JSON.stringify(request.payload)) > hello.runtime.max_payload_bytes) return unavailable()
    const wait = request.method === 'request' ? config.requestTimeoutMs ?? hello.runtime.request_timeout_ms : config.responseWaitMs ?? hello.runtime.response_wait_ms
    const budget = request.method === 'request' ? AbortSignal.any([signal, AbortSignal.timeout(wait)]) : signal
    let job: { session: string; scan_id: string } | undefined
    let approved = false
    try {
      const submitted = await client.submit({ session, policy_scope: `${config.host}.${request.method === 'request' ? 'user_input' : request.tool.startsWith('mcp__') ? 'mcp_result' : 'tool_result'}`, direction: request.method, tool: request.tool, call_id: request.callId, payload: request.payload }, budget)
      job = { session, scan_id: submitted.scan_id }
      let result = await waitForScan(client, job, wait, budget)
      if (result.status === 'pending' && result.job_status === undefined) result = { ...result, job_status: 'queued' }
      approved = result.status === 'approved' && !budget.aborted
      if (request.method === 'response') {
        const visible = await autoRedact(result, () => client.readRedacted(job!, budget))
        if (visible.status === 'redacted') return { ...scanResult(result, false) as object, status: 'redacted', result: visible.result! }
      }
      return scanResult(result, request.method === 'response')
    } finally {
      // Pending responses survive the ephemeral connection for later retrieval.
      if (request.method === 'request' && job && !approved) void client.cancel(job).catch(() => {})
    }
  }
  const server = createServer(socket => {
    if (closing || sockets.size >= 32) { socket.destroy(); return }
    sockets.add(socket)
    if (idle) clearTimeout(idle)
    const caller = new AbortController()
    socket.on('error', () => {})
    socket.once('close', () => { sockets.delete(socket); caller.abort(); if (!closing && sockets.size === 0) idle = setTimeout(() => void stop(), IDLE_MS) })
    void (async () => {
      const signal = AbortSignal.any([caller.signal, shutdown.signal, AbortSignal.timeout(CALL_TIMEOUT)])
      try {
        const frame = await readFrame(socket, AbortSignal.any([signal, AbortSignal.timeout(10_000)]))
        if (!record(frame) || frame.version !== 1 || typeof frame.requestId !== 'string' || !/^[a-f0-9-]{36}$/.test(frame.requestId) ||
            typeof frame.capability !== 'string' || frame.capability.length !== capability.length ||
            !timingSafeEqual(Buffer.from(frame.capability), Buffer.from(capability)) || !validRequest(frame.request)) throw brokerFailure()
        const request = frame.request
        let value: JsonValue
        try {
          if (frame.digest !== digest && request.method !== 'close') throw brokerFailure()
          value = await dispatch(request, signal)
          if (request.method !== 'close') sessions.assertUsable(id)
        } catch { value = request.method === 'close' ? { closed: false } : unavailable() }
        if (!signal.aborted) writeFrame(socket, { version: 1, requestId: frame.requestId, value })
        socket.end()
        if (request.method === 'close') void stop()
      } catch { socket.destroy() }
    })()
  })
  const stop = async () => {
    if (closing) return
    closing = true
    if (idle) clearTimeout(idle)
    shutdown.abort()
    server.close()
    await scanner?.close()
    await runtimeSessions?.close()
    for (const socket of sockets) socket.end()
    const force = setTimeout(() => { for (const socket of sockets) socket.destroy() }, 250)
    force.unref()
  }
  const terminated = () => { void stop() }
  try {
    process.chdir(config.cwd)
    // Bound the socket's creation permissions as well as its final mode.
    const mask = process.umask(0o077)
    try {
      await new Promise<void>((resolveReady, reject) => {
        server.once('error', reject)
        server.listen(socketPath, () => { server.off('error', reject); resolveReady() })
      })
    } finally { process.umask(mask) }
    await chmod(socketPath, 0o600)
    process.on('SIGTERM', terminated); process.on('SIGINT', terminated)
    server.on('error', terminated)
    idle = setTimeout(() => void stop(), IDLE_MS)
    await new Promise<void>(resolveClosed => server.once('close', resolveClosed))
  } catch { await stop() }
  finally {
    shutdown.abort()
    process.off('SIGTERM', terminated); process.off('SIGINT', terminated)
    if (idle) clearTimeout(idle)
    await scanner?.close()
    await runtimeSessions?.close()
    if (snapshot) await unlink(snapshot).catch(() => {})
    try { if ((await owner(lockPath)).pid === process.pid) await unlink(lockPath) } catch { /* Fail closed on changed ownership. */ }
  }
}
