import { chatCommand, controlChat } from './chat-control.ts'
import type { Context } from '@deepseek-ai/cordis'
import { createHash } from 'node:crypto'
import type { ProtocolEventSink } from './protocol-events.ts'
import { elapsed, hashProtocolValue } from './protocol-events.ts'
import { receipt } from './receipts.ts'
import type { SessionState } from './sessions.ts'
import { textPayload, userPromptText } from './text.ts'
import { waitForScan } from './wait.ts'

export function registerPromptGate(
  ctx: Context,
  sessions: SessionState,
  signal: AbortSignal,
  events: ProtocolEventSink,
  overrideMs?: number,
  enabled: (session: string) => boolean = () => true,
  controls?: { executable?: string; paused(session: string): boolean },
): void {
  const approved = new Map<string, Set<string>>()
  const handledControls = new Map<string, Set<string>>()
  ctx.on('agent/disposed', ({ agent }) => { approved.delete(String(agent.id)); handledControls.delete(String(agent.id)) })
  ctx.on('llm/stream', async function* (options, next) {
    if (signal.aborted) throw new Error('Patronus security gate is inactive.')
    const session = String(options.sessionId ?? '')
    if (controls) {
      const latestUser = options.messages.filter(message => message.source.kind === 'user').at(-1)
      const action = latestUser && chatCommand(userPromptText([latestUser]))
      if (action) {
        // The host displays the bounded local status; no model call executes this command.
        const identity = String(latestUser.id)
        const handled = handledControls.get(session) ?? new Set<string>()
        const text = await controlChat('deepseek', session, handled.has(identity) ? 'status' : action, controls.executable)
        handled.add(identity)
        handledControls.set(session, handled)
        throw new Error(text)
      }
      if (controls.paused(session)) { yield* next(); return }
    }
    sessions.assertUsable(session)
    if (!enabled(session)) { yield* next(); return }
    const sessionApproved = approved.get(session) ?? new Set<string>()
    const pending = options.messages.flatMap(message => {
      if (message.source.kind !== 'user') return []
      const text = userPromptText([message])
      if (controls && chatCommand(text)) return []
      const identity = createHash('sha256').update(JSON.stringify([String(message.id), text])).digest('hex')
      return text.length > 0 && !sessionApproved.has(identity) ? [{ identity, text }] : []
    })
    if (pending.length === 0) {
      yield* next()
      return
    }

    const text = pending.flatMap(message => message.text)
    const identity = createHash('sha256').update(JSON.stringify(pending.map(message => message.identity))).digest('hex')
    const payload = textPayload(text)
    const payloadHash = hashProtocolValue(payload)
    const started = performance.now()
    let scanId = ''
    let completed = false
    try {
      const runtime = await sessions.runtime(session, signal)
      const waitMs = overrideMs ?? runtime.hello.runtime.request_timeout_ms
      const submission = await runtime.client.submit({
        session: sessions.capability(session), direction: 'request', policy_scope: 'deepseek.user_input', tool: 'user_prompt',
        call_id: identity, payload,
      }, signal)
      scanId = submission.scan_id
      events.emit({ kind: 'scan_started', direction: 'request', tool: 'user_prompt', session_id: session, scan_id: scanId, status: submission.status, duration_ms: elapsed(started), payload_hash: payloadHash })
      const result = await waitForScan(runtime.client, { session: sessions.capability(session), scan_id: scanId }, waitMs, signal)
      events.emit({ kind: 'scan_completed', direction: 'request', tool: 'user_prompt', session_id: session, scan_id: scanId, status: result.status, duration_ms: elapsed(started), payload_hash: payloadHash })
      completed = true
      if (result.status !== 'approved') throw new Error(JSON.stringify(receipt(result, 'request')))
      for (const message of pending) sessionApproved.add(message.identity)
      approved.set(session, sessionApproved)
      yield* next()
    } catch (error) {
      if (!completed) events.emit({ kind: 'scan_failed', direction: 'request', tool: 'user_prompt', session_id: session, ...(scanId ? { scan_id: scanId } : {}), status: 'failed', duration_ms: elapsed(started), payload_hash: payloadHash })
      throw error
    }
  })
}
