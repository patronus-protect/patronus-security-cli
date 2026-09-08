import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { patronusRoot } from './settings.ts'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import { executablePath, type LocalClientConfig } from './client.ts'

const SCHEMA = 'patronus.protocol.event.v1'

export interface ProtocolEvent {
  kind: string
  direction: 'request' | 'response' | 'status' | 'static'
  tool: string
  session_id: string
  payload_hash: string
  scan_id?: string
  status?: string
  duration_ms?: number
}

export interface ProtocolEventSink {
  emit(event: ProtocolEvent): void
  close?(): Promise<void>
}

export const hashProtocolValue = (value: JsonValue | string): string =>
  `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`

/** Best-effort metadata-only bridge to the scanner-owned protocol store. */
export class ProtocolEvents implements ProtocolEventSink {
  private readonly pending = new Set<Promise<void>>()

  constructor(private readonly config: LocalClientConfig, private readonly root = patronusRoot()) {}

  emit(event: ProtocolEvent): void {
    const sanitized = {
      schema: SCHEMA,
      timestamp: new Date().toISOString(),
      host: 'deepseek',
      session_id: hashProtocolValue(event.session_id),
      event: event.kind,
      direction: event.direction,
      tool_name: event.tool,
      ...(event.scan_id === undefined ? {} : { scan_id: event.scan_id }),
      ...(event.status === undefined ? {} : { status: event.status }),
      ...(event.duration_ms === undefined ? {} : { duration_ms: Math.max(0, Math.round(event.duration_ms)) }),
      payload_hash: event.payload_hash,
    }
    const write = this.append(JSON.stringify(sanitized)).catch(() => {})
    this.pending.add(write)
    void write.finally(() => this.pending.delete(write))
  }

  async close(): Promise<void> {
    await Promise.all(this.pending)
    await this.append('', ['render', '--root', this.root]).catch(() => {})
  }

  private append(serialized: string, args = ['append', '--journal-only', '--root', this.root]): Promise<void> {
    return new Promise((resolve, reject) => {
      let child
      try {
        child = spawn(executablePath(this.config.executable), ['protocol', ...args], {
          shell: false, stdio: ['pipe', 'ignore', 'ignore'],
        })
      } catch { reject(Error('Patronus protocol append failed.')); return }
      let settled = false
      const finish = (ok: boolean) => { if (!settled) { settled = true; clearTimeout(timer); if (ok) resolve(); else reject(Error('Patronus protocol append failed.')) } }
      const timer = setTimeout(() => { child.kill('SIGKILL'); finish(false) }, 10_000)
      child.once('error', () => finish(false))
      child.once('close', code => finish(code === 0))
      child.stdin.once('error', () => finish(false))
      child.stdin.end(serialized)
    })
  }
}

export const elapsed = (started: number): number => performance.now() - started
