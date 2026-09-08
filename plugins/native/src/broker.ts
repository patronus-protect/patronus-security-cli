import { patronusRoot } from '../../deepseek/src/settings.ts'
import { spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, mkdir, open, realpath } from 'node:fs/promises'
import { connect, type Socket } from 'node:net'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import type { JsonValue } from './types.ts'
import { SessionState } from '../../deepseek/src/sessions.ts'
import type { TextPayload } from '../../deepseek/src/protocol.ts'
import { boundedMilliseconds } from '../../deepseek/src/wait.ts'

export interface BrokerConfig {
  host: 'codex' | 'claude'
  sessionId: string
  cwd: string
  stateDir?: string
  executable?: string
  configPath?: string
  responseWaitMs?: number
  requestTimeoutMs?: number
}
export type BrokerRequest =
  | { method: 'request' | 'response'; tool: string; callId: string; payload: TextPayload }
  | { method: 'check' | 'read_redacted'; scanId: string }
  | { method: 'static'; kind: 'repo' | 'directory' | 'file' | 'url' | 'mcp'; path: string; server?: string }
  | { method: 'close' }

export const MAX_PAYLOAD = 10 * 1024 * 1024
export const MAX_FRAME = 16 * 1024 * 1024
export const CALL_TIMEOUT = 320_000
export const unavailable = (): JsonValue => ({ scan_id: '', status: 'unavailable' })
export const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value)
export const brokerFailure = () => new Error('Patronus native broker unavailable.')
const text = (value: unknown, max: number): value is string => typeof value === 'string' && value.length > 0 && value.length <= max && !value.includes('\0')
const hash = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex')

async function repositoryRoot(start: string): Promise<string | undefined> {
  for (let current = start; ; current = dirname(current)) {
    try { await lstat(join(current, '.git')); return current }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw brokerFailure() }
    if (dirname(current) === current) return undefined
  }
}

function defaultStateDir(): string {
  return join(patronusRoot(), 'native-sessions')
}

export function validRequest(value: unknown): value is BrokerRequest {
  if (!record(value) || typeof value.method !== 'string') return false
  let keys: string[]
  switch (value.method) {
    case 'request': case 'response':
      keys = ['method', 'tool', 'callId', 'payload']
      if (!text(value.tool, 256) || !text(value.callId, 256) || !Object.hasOwn(value, 'payload')) return false
      if (typeof value.payload !== 'string' && !(Array.isArray(value.payload) && value.payload.every(item => typeof item === 'string'))) return false
      try { if (Buffer.byteLength(JSON.stringify(value.payload)) > MAX_PAYLOAD) return false } catch { return false }
      break
    case 'check': case 'read_redacted':
      keys = ['method', 'scanId']
      if (typeof value.scanId !== 'string' || !/^[a-f0-9]{32}$/.test(value.scanId)) return false
      break
    case 'static':
      keys = ['method', 'kind', 'path', 'server']
      if (value.server !== undefined && (value.kind !== 'mcp' || !text(value.server, 256))) return false
      if (typeof value.kind !== 'string' || !['repo', 'directory', 'file', 'url', 'mcp'].includes(value.kind) || !text(value.path, 8192) || (!(value.kind === 'url' || value.kind === 'mcp' && value.path.startsWith('https://')) && !isAbsolute(value.path))) return false
      break
    case 'close': keys = ['method']; break
    default: return false
  }
  return Object.keys(value).every(key => keys.includes(key))
}

/** Only the OS's fixed macOS aliases are normalized; private-path symlinks are rejected. */
function systemPath(path: string): string {
  const absolute = resolve(path)
  return process.platform === 'darwin' ? absolute.replace(/^\/tmp(?=\/|$)/, '/private/tmp').replace(/^\/var(?=\/|$)/, '/private/var') : absolute
}

export async function privateDirectory(path: string): Promise<void> {
  const uid = process.getuid?.()
  if (uid === undefined || !isAbsolute(path)) throw brokerFailure()
  const ancestors: string[] = []
  for (let current = path; ; current = dirname(current)) { ancestors.unshift(current); if (dirname(current) === current) break }
  for (const current of ancestors) {
    try { await mkdir(current, { mode: 0o700 }) } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw brokerFailure() }
    const info = await lstat(current)
    const systemTemp = info.uid === 0 && (info.mode & 0o1000) !== 0 && (current === '/tmp' || current === '/private/tmp')
    if (!info.isDirectory() || info.isSymbolicLink() || (info.uid !== uid && info.uid !== 0) ||
        (!systemTemp && (info.mode & 0o022) !== 0) ||
        (current === path && (info.uid !== uid || (info.mode & 0o077) !== 0))) throw brokerFailure()
  }
}

export async function readPrivate(path: string, limit = 16_384, maxLinks = 1): Promise<string> {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const info = await file.stat()
    if (!info.isFile() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0 || info.nlink < 1 || info.nlink > maxLinks || info.size > limit) throw brokerFailure()
    return await file.readFile('utf8')
  } finally { await file.close() }
}

/** Internal shared preparation. No scanner or candidate file content is read here. */
async function prepareSession(input: BrokerConfig) {
  if (!['darwin', 'linux'].includes(process.platform)) throw brokerFailure()
  if (!record(input) || !['codex', 'claude'].includes(input.host) || !text(input.sessionId, 1024) || !text(input.cwd, 4096) || !isAbsolute(input.cwd) ||
      Object.keys(input).some(key => !['host', 'sessionId', 'cwd', 'stateDir', 'executable', 'configPath', 'responseWaitMs', 'requestTimeoutMs'].includes(key))) throw brokerFailure()
  for (const value of [input.stateDir, input.executable, input.configPath]) if (value !== undefined && (!text(value, 4096) || !isAbsolute(value))) throw brokerFailure()
  if (input.responseWaitMs !== undefined) boundedMilliseconds(input.responseWaitMs, 'responseWaitMs')
  if (input.requestTimeoutMs !== undefined) boundedMilliseconds(input.requestTimeoutMs, 'requestTimeoutMs', 1)
  const cwd = await realpath(input.cwd)
  const stateDir = systemPath(input.stateDir ?? defaultStateDir())
  const repository = await repositoryRoot(cwd) ?? cwd
  // The fixed user-owned default is trusted infrastructure, even when the
  // selected project is the home directory. Overrides must stay outside it.
  if (input.stateDir !== undefined) {
    const fromRepository = relative(repository, stateDir)
    if (fromRepository === '' || (fromRepository !== '..' && !fromRepository.startsWith(`..${sep}`) && !isAbsolute(fromRepository))) throw brokerFailure()
  }
  await privateDirectory(stateDir)
  const config: BrokerConfig = { host: input.host, sessionId: input.sessionId, cwd, stateDir,
    ...(input.executable !== undefined ? { executable: input.executable } : {}),
    ...(input.configPath !== undefined ? { configPath: input.configPath } : {}),
    ...(input.responseWaitMs !== undefined ? { responseWaitMs: input.responseWaitMs } : {}),
    ...(input.requestTimeoutMs !== undefined ? { requestTimeoutMs: input.requestTimeoutMs } : {}),
  }
  if (Buffer.byteLength(JSON.stringify(config)) > 16_384) throw brokerFailure()
  const id = JSON.stringify([config.host, config.sessionId])
  const directory = join(stateDir, createHash('sha256').update(id).digest('hex'))
  await privateDirectory(directory)
  const sessions = new SessionState({ stateDir })
  let capability: string
  const capabilityDeadline = Date.now() + 1000
  for (;;) {
    try { capability = sessions.capability(id); break }
    catch {
      // Another hook can see O_EXCL's empty file before the creator writes it.
      // The write may also finish between the failed read and this check.
      const current = await readPrivate(join(directory, 'capability'), 128)
      if (Date.now() >= capabilityDeadline || (current !== '' && !/^[a-f0-9-]{36}$/.test(current))) throw brokerFailure()
      await delay(5)
    }
  }
  return { config, id, directory, sessions, capability, repository }
}


export async function prepareBroker(input: BrokerConfig) {
  const prepared = await prepareSession(input)
  const { config } = prepared
  const socketRoot = join(systemPath(patronusRoot()), 'sockets')
  await privateDirectory(socketRoot)
  const key = hash([config.stateDir, config.host, config.sessionId]).slice(0, 24)
  const socketPath = join(socketRoot, `${key}.sock`)
  if (Buffer.byteLength(socketPath) > 103) throw brokerFailure()
  return { ...prepared, socketRoot, socketPath, key, digest: hash(config) }
}

export function writeFrame(socket: Socket, value: unknown): void {
  const body = Buffer.from(JSON.stringify(value))
  if (body.length > MAX_FRAME) throw brokerFailure()
  const header = Buffer.alloc(4)
  header.writeUInt32BE(body.length)
  socket.write(Buffer.concat([header, body]))
}

export function readFrame(socket: Socket, signal: AbortSignal): Promise<unknown> {
  return new Promise((resolveValue, reject) => {
    const chunks: Buffer[] = []
    let bytes = 0
    let expected: number | undefined
    let header = Buffer.alloc(0)
    const cleanup = () => { socket.off('data', data); socket.off('error', fail); socket.off('end', fail); socket.off('close', fail); signal.removeEventListener('abort', fail) }
    const fail = () => { cleanup(); reject(brokerFailure()) }
    const data = (chunk: Buffer) => {
      bytes += chunk.length
      if (bytes > MAX_FRAME + 4) { fail(); socket.destroy(); return }
      chunks.push(chunk)
      if (header.length < 4) header = Buffer.concat([header, chunk.subarray(0, 4 - header.length)])
      if (header.length === 4 && expected === undefined) expected = header.readUInt32BE()
      if (expected !== undefined && (expected < 2 || expected > MAX_FRAME || bytes > expected + 4)) { fail(); socket.destroy(); return }
      if (expected !== undefined && bytes === expected + 4) {
        cleanup()
        try { resolveValue(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, bytes).subarray(4)))) }
        catch { reject(brokerFailure()) }
      }
    }
    socket.on('data', data); socket.once('error', fail); socket.once('end', fail); socket.once('close', fail)
    signal.addEventListener('abort', fail, { once: true })
    if (signal.aborted) fail()
  })
}

async function connectPrivate(path: string, signal: AbortSignal): Promise<Socket> {
  const info = await lstat(path)
  if (!info.isSocket() || info.isSymbolicLink() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0) throw brokerFailure()
  return new Promise((resolveSocket, reject) => {
    const socket = connect(path)
    const fail = () => { signal.removeEventListener('abort', fail); socket.destroy(); reject(brokerFailure()) }
    const error = (cause: NodeJS.ErrnoException) => {
      signal.removeEventListener('abort', fail); socket.destroy()
      reject(Object.assign(brokerFailure(), { code: cause.code }))
    }
    socket.once('error', error)
    signal.addEventListener('abort', fail, { once: true })
    socket.once('connect', () => { signal.removeEventListener('abort', fail); socket.off('error', error); socket.on('error', () => {}); resolveSocket(socket) })
    if (signal.aborted) fail()
  })
}

/** A single private RPC per ephemeral hook. Payloads/capabilities never enter argv. */
export async function callBroker(config: BrokerConfig, request: BrokerRequest, signal?: AbortSignal): Promise<JsonValue> {
  const failure = (): JsonValue => request?.method === 'close' ? { closed: false } : unavailable()
  let socket: Socket | undefined
  const deadline = AbortSignal.any([signal ?? new AbortController().signal, AbortSignal.timeout(CALL_TIMEOUT)])
  try {
    if (!['darwin', 'linux'].includes(process.platform)) return request?.method === 'close' ? failure()
      : { scan_id: '', status: 'unavailable', reason: 'unsupported_platform' }
    if (!validRequest(request) || deadline.aborted) return failure()
    const prepared = await prepareBroker(config)
    const startupDeadline = Date.now() + 15_000
    let starts = 0
    let lastStart = 0
    while (!socket) {
      deadline.throwIfAborted()
      try { socket = await connectPrivate(prepared.socketPath, deadline) }
      catch (error) {
        if (!['ENOENT', 'ECONNREFUSED'].includes((error as NodeJS.ErrnoException).code ?? '')) throw brokerFailure()
        if (Date.now() >= startupDeadline) throw brokerFailure()
        // A previous daemon may have stopped listening but still be releasing
        // its scanner/lock. Retry election, never replay an already-sent request.
        if (starts < 3 && Date.now() - lastStart >= 2000) {
          const child = spawn(process.execPath, [fileURLToPath(import.meta.url), 'daemon', Buffer.from(JSON.stringify(prepared.config)).toString('base64url')], {
            cwd: prepared.config.cwd, detached: true, shell: false, stdio: 'ignore',
          })
          child.on('error', () => {}); child.unref(); starts++; lastStart = Date.now()
        }
        await delay(50, undefined, { signal: deadline })
      }
    }
    const requestId = randomUUID()
    const response = readFrame(socket, deadline)
    writeFrame(socket, { version: 1, requestId, capability: prepared.capability, digest: prepared.digest, request })
    const received = await response
    if (!record(received) || received.version !== 1 || received.requestId !== requestId || !Object.hasOwn(received, 'value')) throw brokerFailure()
    if (request.method === 'close') {
      socket.destroy()
      const until = Date.now() + 3000
      while (Date.now() < until) {
        try { await lstat(prepared.socketPath) } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') break; throw brokerFailure() }
        await delay(20, undefined, { signal: deadline })
      }
    }
    return received.value as JsonValue
  } catch { return failure() }
  finally { socket?.destroy() }
}
