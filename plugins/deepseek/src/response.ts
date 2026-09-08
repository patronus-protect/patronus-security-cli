import type { Context } from '@deepseek-ai/cordis'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import type { PostToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import type { RuntimeClient } from './protocol.ts'
import type { SessionRuntime } from './sessions.ts'
import { fingerprint, projectResult, isNativeCancellation } from './host.ts'
import { blocked, receipt } from './receipts.ts'
import { waitForScan } from './wait.ts'
import { autoRedact } from './auto-redaction.ts'
import { elapsed, hashProtocolValue, type ProtocolEventSink } from './protocol-events.ts'
import { textPayload, toolResultText } from './text.ts'

export interface Gate {
  enabledFor?(exec: ToolExecution): boolean
  runtimeFor(exec: ToolExecution): Promise<SessionRuntime>
  signal: AbortSignal
  isOwnTool(exec: ToolExecution): boolean
  sessionFor(exec: ToolExecution): string
  unsupported(exec: ToolExecution): void
  events: ProtocolEventSink
}

export function registerResponseGate(ctx: Context, gate: Gate, overrideMs?: number): void {
  const bypassed = new WeakSet<ToolExecution>()
  const expected = new WeakMap<ToolExecution, string>()
  const finish = (exec: ToolExecution, result: Readonly<ToolExecutionResult>, decision: PostToolDecision) => {
    expected.set(exec, fingerprint(projectResult(result, decision)))
    return decision
  }
  ctx.on('tools/post-execute', async (exec, result, next) => {
    let job: { session: string; scan_id: string } | undefined
    let client: RuntimeClient | undefined
    const started = performance.now()
    let payloadHash = hashProtocolValue('unavailable')
    let session = ''
    try {
      const decision = await next()
      if (gate.enabledFor?.(exec) === false) { bypassed.add(exec); return decision }
      const envelope = projectResult(result, decision)
      const text = toolResultText(envelope)
      if (gate.isOwnTool(exec)) return decision
      if (text.length === 0) return finish(exec, result, decision)
      const payload = textPayload(text)
      payloadHash = hashProtocolValue(payload)
      const runtime = await gate.runtimeFor(exec)
      client = runtime.client
      const waitMs = overrideMs ?? runtime.hello.runtime.response_wait_ms
      const signal = AbortSignal.any([exec.signal, gate.signal])
      session = gate.sessionFor(exec)
      const submission = await client.submit({ session, direction: 'response', policy_scope: exec.name.startsWith('mcp__') ? 'deepseek.mcp_result' : 'deepseek.tool_result', tool: exec.name, call_id: String(exec.callId), payload }, signal)
      job = { session, scan_id: submission.scan_id }
      gate.events.emit({ kind: 'scan_started', direction: 'response', tool: exec.name, session_id: session, scan_id: submission.scan_id, status: submission.status, duration_ms: elapsed(started), payload_hash: payloadHash })
      const scanned = await autoRedact(await waitForScan(client, job, waitMs, signal), () => client!.readRedacted(job!, signal))
      gate.events.emit({ kind: 'scan_completed', direction: 'response', tool: exec.name, session_id: session, scan_id: scanned.scan_id, status: scanned.status, duration_ms: elapsed(started), payload_hash: payloadHash })
      if (scanned.status === 'approved' && ctx.tools.get(exec.name, exec.agent)?.finalizeContent === undefined) {
        return finish(exec, result, decision)
      }
      const metadata = receipt(scanned) as Record<string, JsonValue>
      if (scanned.status === 'approved') {
        metadata.message = 'The source tool already executed and its scan is approved. Call patronus_check_result with this scan_id to retrieve the result. Do not rerun the source tool.'
      }
      return finish(exec, result, blocked(metadata))
    } catch {
      gate.events.emit({ kind: 'scan_failed', direction: 'response', tool: exec.name, session_id: session || String(exec.agent?.id ?? ''), ...(job ? { scan_id: job.scan_id } : {}), status: 'failed', duration_ms: elapsed(started), payload_hash: payloadHash })
      if (job && client) void client.cancel(job).catch(() => {})
      return finish(exec, result, blocked(receipt({ scan_id: job?.scan_id ?? '', status: 'failed' })))
    }
  })
  ctx.on('tools/result', (exec, result) => {
    if (bypassed.delete(exec)) return
    if (gate.isOwnTool(exec)) {
      expected.delete(exec)
      return
    }
    // The host has no post-finalizer rewrite hook. Stop the next model request
    // if a finalizer/outer middleware changed the exact projection we checked.
    if (expected.get(exec) !== fingerprint(result) && !isNativeCancellation(exec, result)) gate.unsupported(exec)
    expected.delete(exec)
  })
}
