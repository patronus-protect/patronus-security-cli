import { patronusRoot } from './settings.ts'
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { accessSync, constants, realpathSync, existsSync } from 'node:fs'
import { delimiter, isAbsolute, join, relative } from 'node:path'
import type { JobParams, RedactedResult, RuntimeClient, RuntimeHello, ScanResult, SubmitParams } from './protocol.ts'

export type { JobParams, RedactedResult, RuntimeClient, RuntimeHello, ScanResult, SubmitParams } from './protocol.ts'
export interface LocalClientConfig {
  executable?: string
  configPath?: string
  stateDir?: string
  /** Budget for prepared model loading before the runtime can answer hello. */
  startupTimeoutMs?: number
}
const MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
const MAX_LINE_BYTES = MAX_PAYLOAD_BYTES + 1024 * 1024
const RPC_TIMEOUT_MS = 90_000
const STARTUP_TIMEOUT_MS = 320_000
const statuses = new Set(['pending', 'approved', 'dangerous', 'failed', 'incomplete', 'cancelled', 'expired', 'unavailable'])
const failure = () => new Error('Patronus local runtime unavailable or returned an invalid response.')
const record = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)

/** Resolve only installed absolute PATH entries, never a repository-relative binary. */
export function executablePath(configured?: string): string {
  if (configured !== undefined) {
    if (!isAbsolute(configured)) throw new Error('Patronus executable must be an absolute installed CLI path.')
    return configured
  }
  for (const directory of (process.env.PATH ?? '').split(delimiter)) {
    if (!isAbsolute(directory)) continue
    try {
      const candidate = realpathSync(join(directory, 'patronus-security-scanner'))
      const fromWorkdir = relative(realpathSync(process.cwd()), candidate)
      if (!fromWorkdir.startsWith('..') && !isAbsolute(fromWorkdir)) continue
      accessSync(candidate, constants.X_OK)
      return candidate
    } catch { /* Try the next installed PATH entry. */ }
  }
  throw new Error('Install patronus-security-scanner on PATH before starting the plugin.')
}

interface Pending { resolve(value: unknown): void; reject(error: Error): void; cleanup(): void }

/** One private, persistent stdio connection; stdout is never copied into model errors. */
export class LocalClient implements RuntimeClient {
  private readonly child: ChildProcessWithoutNullStreams
  private readonly pending = new Map<string, Pending>()
  private chunks: Buffer[] = []
  private bufferedBytes = 0
  private closed = false
  private closing?: Promise<void>
  private greeting?: Promise<RuntimeHello>
  private readonly startupTimeoutMs: number

  constructor(config: LocalClientConfig = {}) {
    if (!config.stateDir || !isAbsolute(config.stateDir)) throw new Error('Patronus local runtime requires an absolute private session store path.')
    this.startupTimeoutMs = config.startupTimeoutMs ?? STARTUP_TIMEOUT_MS
    if (!Number.isSafeInteger(this.startupTimeoutMs) || this.startupTimeoutMs < 1 || this.startupTimeoutMs > 900_000) {
      throw new Error('Patronus startupTimeoutMs must be an integer between 1 and 900000.')
    }
    const args = ['serve', '--stdio']
    const sharedConfig = join(patronusRoot(), 'config.toml')
    const configPath = config.configPath ?? (existsSync(sharedConfig) ? sharedConfig : undefined)
    if (configPath !== undefined) args.push('--config', configPath)
    args.push('--state-dir', config.stateDir)
    this.child = spawn(executablePath(config.executable), args, { shell: false, stdio: 'pipe' })
    this.child.stdout.on('data', (chunk: Buffer) => this.receive(chunk))
    this.child.stderr.on('data', () => {}) // Drain diagnostics without retaining private content.
    this.child.on('error', () => this.close())
    this.child.on('exit', () => this.close())
    this.child.stdin.on('error', () => this.close())
  }

  hello(signal?: AbortSignal): Promise<RuntimeHello> {
    this.greeting ??= this.rpc('hello', {}, signal, this.startupTimeoutMs).then(value => {
      if (!record(value) || value.protocol_version !== 1 || !['local', 'api', 'hybrid'].includes(String(value.provider)) || value.ready !== true ||
          typeof value.scanner_version !== 'string' || typeof value.ark_version !== 'string' || !record(value.runtime)) throw failure()
      for (const key of ['response_wait_ms', 'request_timeout_ms', 'scan_timeout_ms', 'max_payload_bytes']) {
        const number = value.runtime[key]
        if (!Number.isSafeInteger(number) || (number as number) < (key === 'response_wait_ms' ? 0 : 1) ||
            (number as number) > (key === 'max_payload_bytes' ? MAX_PAYLOAD_BYTES : 300_000)) throw failure()
      }
      return value as unknown as RuntimeHello
    }).catch(() => { this.close(); throw failure() })
    return this.greeting
  }

  async submit(params: SubmitParams, signal?: AbortSignal): Promise<{ scan_id: string; status: 'pending' }> {
    const hello = await this.hello(signal)
    if (Buffer.byteLength(JSON.stringify(params.payload)) > hello.runtime.max_payload_bytes) throw failure()
    const value = await this.rpc('submit', params, signal)
    if (!record(value) || typeof value.scan_id !== 'string' || value.scan_id.length > 256 || value.status !== 'pending') throw failure()
    return { scan_id: value.scan_id, status: 'pending' }
  }

  async check(params: JobParams, signal?: AbortSignal): Promise<ScanResult> {
    const value = await this.rpc('check', params, signal)
    if (record(value) && value.status === 'unavailable' && value.scan_id === undefined && !Object.hasOwn(value, 'result')) {
      return { scan_id: params.scan_id, status: 'unavailable' }
    }
    if (!record(value) || value.scan_id !== params.scan_id || !statuses.has(String(value.status)) ||
        (value.status !== 'approved' && Object.hasOwn(value, 'result'))) throw failure()
    return value as unknown as ScanResult
  }

  async readRedacted(params: JobParams, signal?: AbortSignal): Promise<RedactedResult> {
    const deadline = Date.now() + RPC_TIMEOUT_MS
    let value: unknown
    for (;;) {
      value = await this.rpc('read_redacted', params, signal, Math.max(1, deadline - Date.now()))
      if (!record(value) || value.scan_id !== params.scan_id || value.status !== 'pending') break
      if (Object.hasOwn(value, 'result') || Date.now() >= deadline || signal?.aborted) throw failure()
      await new Promise<void>(resolve => setTimeout(resolve, 50))
    }
    if (record(value) && value.status === 'unavailable' && value.scan_id === undefined && !Object.hasOwn(value, 'result')) {
      return { scan_id: params.scan_id, status: 'unavailable' }
    }
    if (!record(value) || value.scan_id !== params.scan_id || !['redacted', 'unavailable'].includes(String(value.status)) ||
        (value.status !== 'redacted' && Object.hasOwn(value, 'result'))) throw failure()
    return value as unknown as RedactedResult
  }

  cancel(params: JobParams, signal?: AbortSignal): Promise<unknown> { return this.rpc('cancel', params, signal) }

  close(): Promise<void> {
    if (this.closing) return this.closing
    this.closed = true
    this.chunks = []
    this.bufferedBytes = 0
    for (const request of this.pending.values()) { request.cleanup(); request.reject(failure()) }
    this.pending.clear()
    this.child.stdin.destroy()
    this.closing = new Promise(resolve => {
      if (this.child.exitCode !== null || this.child.signalCode !== null || this.child.pid === undefined) { resolve(); return }
      const kill = setTimeout(() => this.child.kill('SIGKILL'), 1_000)
      this.child.once('exit', () => { clearTimeout(kill); resolve() })
      this.child.kill('SIGTERM')
    })
    return this.closing
  }

  private rpc(method: string, params: unknown, signal?: AbortSignal, timeoutMs = RPC_TIMEOUT_MS): Promise<unknown> {
    if (this.closed || signal?.aborted || this.pending.size >= 128) return Promise.reject(failure())
    const id = randomUUID()
    let line: string
    try { line = JSON.stringify({ id, method, params }) + '\n' } catch { return Promise.reject(failure()) }
    if (Buffer.byteLength(line) > MAX_LINE_BYTES || this.child.stdin.writableLength + Buffer.byteLength(line) > MAX_LINE_BYTES * 2) return Promise.reject(failure())
    return new Promise((resolve, reject) => {
      const abort = () => { this.pending.delete(id); cleanup(); reject(failure()) }
      const timer = setTimeout(abort, timeoutMs)
      const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', abort) }
      this.pending.set(id, { resolve, reject, cleanup })
      signal?.addEventListener('abort', abort, { once: true })
      this.child.stdin.write(line, error => { if (error) this.close() })
    })
  }

  private receive(chunk: Buffer): void {
    if (this.closed) return
    let offset = 0
    while (offset < chunk.length) {
      const newline = chunk.indexOf(10, offset)
      const end = newline === -1 ? chunk.length : newline
      const part = chunk.subarray(offset, end)
      this.bufferedBytes += part.length
      if (this.bufferedBytes > MAX_LINE_BYTES) { this.close(); return }
      this.chunks.push(part)
      if (newline === -1) return
      const line = Buffer.concat(this.chunks, this.bufferedBytes)
      this.chunks = []
      this.bufferedBytes = 0
      offset = newline + 1
      let value: unknown
      try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line)) } catch { this.close(); return }
      if (!record(value) || typeof value.id !== 'string' || Object.hasOwn(value, 'result') === Object.hasOwn(value, 'error')) { this.close(); return }
      const request = this.pending.get(value.id)
      if (!request) continue // A cancelled local request may still receive its reply.
      this.pending.delete(value.id)
      request.cleanup()
      if (Object.hasOwn(value, 'error')) request.reject(failure())
      else request.resolve(value.result)
    }
  }
}
