import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir } from 'node:fs/promises'
import { patronusRoot } from '../../deepseek/src/settings.ts'
import type { BrokerConfig, BrokerRequest } from './broker.ts'
import type { JsonValue } from './types.ts'

type Event = {
  schema: 'patronus.protocol.event.v1'
  timestamp: string
  host: BrokerConfig['host']
  session_id: string
  event: string
  direction: 'request' | 'response' | 'status' | 'static'
  tool_name: string
  scan_id?: string
  status: string
  duration_ms: number
  payload_hash: string
}

type Append = (event: Event, root: string, executable?: string) => Promise<void>
export type ProtocolRecorder = (config: BrokerConfig, request: BrokerRequest, run: () => Promise<JsonValue>) => Promise<JsonValue>

const hash = (value: unknown) => `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value)

/** Append one sanitized event. Protocol persistence must never affect hook policy. */
export async function appendProtocolEvent(event: Event, root: string, executable = 'patronus-security-scanner'): Promise<void> {
  await protocolCommand(['append', '--journal-only', '--root', root], root, executable, JSON.stringify(event))
}

async function protocolCommand(args: string[], root: string, executable: string, input = ''): Promise<void> {
  await mkdir(root, { recursive: true, mode: 0o700 })
  await new Promise<void>((resolveDone, reject) => {
    let done = false
    const child = spawn(executable, ['protocol', ...args], { cwd: root, shell: false, stdio: ['pipe', 'ignore', 'ignore'] })
    const finish = (ok: boolean) => { if (!done) { done = true; clearTimeout(timer); if (ok) resolveDone(); else reject(Error('Patronus protocol append failed.')) } }
    const configured = Number(process.env.PATRONUS_PROTOCOL_TIMEOUT_MS ?? 5_000)
    const timeoutMs = Number.isFinite(configured) ? Math.min(10_000, Math.max(100, configured)) : 5_000
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish(false) }, timeoutMs)
    timer.unref()
    child.once('error', () => finish(false)); child.once('close', code => finish(code === 0)); child.stdin.once('error', () => finish(false))
    child.stdin.end(input)
  })
}

function details(request: BrokerRequest) {
  if (request.method === 'request' || request.method === 'response') {
    return { direction: request.method, tool: request.tool, payload: request.payload }
  }
  if (request.method === 'static') return { direction: 'static' as const, tool: 'patronus_scan', payload: { kind: request.kind, path: request.path } }
  if (request.method === 'check') return { direction: 'status' as const, tool: 'patronus_check_result', payload: { scan_id: request.scanId } }
  if (request.method === 'read_redacted') return { direction: 'status' as const, tool: 'patronus_read_redacted', payload: { scan_id: request.scanId } }
  return undefined
}

export async function recordProtocolScan(config: BrokerConfig, request: BrokerRequest, run: () => Promise<JsonValue>, append: Append = appendProtocolEvent): Promise<JsonValue> {
  if (request.method === 'close') {
    const result = await run()
    const root = patronusRoot()
    await protocolCommand(['render', '--root', root], root, config.executable ?? 'patronus-security-scanner').catch(() => {})
    return result
  }
  const item = details(request)
  if (!item) return run()
  const started = Date.now()
  const root = patronusRoot()
  const base = {
    schema: 'patronus.protocol.event.v1' as const,
    host: config.host,
    session_id: hash([config.host, config.sessionId]),
    direction: item.direction,
    tool_name: item.tool,
    payload_hash: hash(item.payload),
  }
  try {
    const result = await run()
    const completed = Date.now()
    const scanId = record(result) && typeof (result.scan_id ?? result.run_id) === 'string' ? String(result.scan_id ?? result.run_id) : undefined
    const status = record(result) && typeof result.status === 'string' ? result.status.toLowerCase() : 'completed'
    await append({ ...base, timestamp: new Date(completed).toISOString(), event: 'scan_completed', status,
      duration_ms: Math.max(0, completed - started), ...(scanId ? { scan_id: scanId } : {}) }, root, config.executable).catch(() => {})
    return result
  } catch (error) {
    const completed = Date.now()
    await append({ ...base, timestamp: new Date(completed).toISOString(), event: 'scan_failed', status: 'failed',
      duration_ms: Math.max(0, completed - started) }, root, config.executable).catch(() => {})
    throw error
  }
}
