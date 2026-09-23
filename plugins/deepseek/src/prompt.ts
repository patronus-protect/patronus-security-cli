import { chatCommand, controlChat } from './chat-control.ts'
import type { Context } from '@deepseek-ai/cordis'
import type { PreStepDecision } from '@deepseek-ai/dsh-agent'
import type { Message } from '@deepseek-ai/dsh-llm'
import { createHash } from 'node:crypto'
import type { ProtocolEventSink } from './protocol-events.ts'
import { elapsed, hashProtocolValue } from './protocol-events.ts'
import { receipt } from './receipts.ts'
import type { SessionState } from './sessions.ts'
import { textPayload, userPromptText } from './text.ts'
import { waitForScan } from './wait.ts'
import { degradedMessage } from './degraded.ts'
import { degradedText, noticeText, scanNotice } from './notice.ts'
import type { ScanResult } from './protocol.ts'
import { consumeIgnoreOnce, hasIgnoreOnce, injectionFinding, issueIgnoreOnce, stripIgnoreOnce } from './ignore-once.ts'

const degraded = new Set(['failed', 'incomplete', 'cancelled', 'expired', 'unavailable'])

function removeConsumedCommand(messages: readonly Message[], pending: ReadonlySet<string>): { messages: Message[]; identities: string[] } {
  const identities: string[] = []
  const cleanMessages = messages.map(message => {
    if (message.source.kind !== 'user') return message
    const identity = createHash('sha256').update(JSON.stringify([String(message.id), userPromptText([message])])).digest('hex')
    if (!pending.has(identity)) return message
    const clean = { ...message, content: message.content.map(block => block.type === 'text' ? { ...block, text: stripIgnoreOnce(block.text) } : block) }
    identities.push(createHash('sha256').update(JSON.stringify([String(message.id), userPromptText([clean])])).digest('hex'))
    return clean
  })
  return { messages: cleanMessages, identities }
}

function warn(decision: PreStepDecision, text?: string): PreStepDecision {
  return decision.kind === 'enter'
    ? { ...decision, messages: [...decision.messages, degradedMessage(text)] }
    : decision
}

/** The note to attach after a prompt scan, if any. */
function promptNote(result: ScanResult): string | undefined {
  if (degraded.has(result.status)) return degradedText(result)
  const notice = scanNotice(result.notice)
  return notice ? noticeText(notice) : undefined
}

export function registerPromptGate(
  ctx: Context,
  sessions: SessionState,
  signal: AbortSignal,
  events: ProtocolEventSink,
  overrideMs?: number,
  enabled: (session: string) => boolean = () => true,
  controls?: { executable?: string; paused(session: string): boolean },
  degradedSessions: Set<string> = new Set(),
): void {
  const approved = new Map<string, Set<string>>()
  const handledControls = new Map<string, Set<string>>()
  ctx.on('agent/disposed', ({ agent }) => { approved.delete(String(agent.id)); handledControls.delete(String(agent.id)) })
  ctx.on('agent/pre-step', async ({ agent, messages }, next): Promise<PreStepDecision> => {
    const session = String(agent.id)
    const warnNow = signal.aborted || degradedSessions.delete(session)
    if (controls?.paused(session) || !enabled(session)) return warnNow ? warn(await next()) : next()
    const sessionApproved = approved.get(session) ?? new Set<string>()
    const pending = messages.flatMap(message => {
      if (message.source.kind !== 'user') return []
      const text = userPromptText([message])
      if (controls && chatCommand(text)) return []
      const identity = createHash('sha256').update(JSON.stringify([String(message.id), text])).digest('hex')
      return text.length > 0 && !sessionApproved.has(identity) ? [{ identity, text }] : []
    })
    if (pending.length === 0) return warnNow ? warn(await next()) : next()
    const text = pending.flatMap(message => message.text)
    const identity = createHash('sha256').update(JSON.stringify(pending.map(message => message.identity))).digest('hex')
    const payload = textPayload(text)
    if (hasIgnoreOnce(payload)) return next() // The llm/stream gate validates and strips it before model access.
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
      if (result.status !== 'approved' && !degraded.has(result.status)) {
        const visible = receipt(result, 'request')
        if (injectionFinding(result) && typeof visible === 'object' && visible !== null && !Array.isArray(visible)) {
          const command = issueIgnoreOnce('deepseek', session, payload)
          if (command) {
            visible.ignore_once = command
            visible.message = 'Injection risk blocked this prompt. Add ignore_once to the same message and resend it within 15 minutes to allow that message once.'
          }
        }
        throw new Error(JSON.stringify(visible))
      }
      for (const message of pending) sessionApproved.add(message.identity)
      approved.set(session, sessionApproved)
      const note = promptNote(result)
      return note || warnNow ? warn(await next(), note) : next()
    } catch (error) {
      if (!completed) events.emit({ kind: 'scan_failed', direction: 'request', tool: 'user_prompt', session_id: session, ...(scanId ? { scan_id: scanId } : {}), status: 'failed', duration_ms: elapsed(started), payload_hash: payloadHash })
      if (completed) throw error
      for (const message of pending) sessionApproved.add(message.identity)
      approved.set(session, sessionApproved)
      return warn(await next(), degradedText({ reason: scanId ? 'scanner_connection_lost' : 'runtime_start_failed' }))
    }
  })
  ctx.on('llm/stream', async function* (options, next) {
    if (signal.aborted) { options.messages.push(degradedMessage()); yield* next(); return }
    const session = String(options.sessionId ?? '')
    if (controls) {
      const latestUser = options.messages.filter(message => message.source.kind === 'user').at(-1)
      const action = latestUser && chatCommand(userPromptText([latestUser]))
      if (action) {
        const identity = String(latestUser.id)
        const handled = handledControls.get(session) ?? new Set<string>()
        const text = await controlChat('deepseek', session, handled.has(identity) ? 'status' : action, controls.executable)
        handled.add(identity)
        handledControls.set(session, handled)
        throw new Error(text)
      }
      if (controls.paused(session)) { yield* next(); return }
    }
    if (!enabled(session)) { yield* next(); return }
    const sessionApproved = approved.get(session) ?? new Set<string>()
    const pending = options.messages.flatMap(message => {
      if (message.source.kind !== 'user') return []
      const text = userPromptText([message])
      if (controls && chatCommand(text)) return []
      const identity = createHash('sha256').update(JSON.stringify([String(message.id), text])).digest('hex')
      return text.length > 0 && !sessionApproved.has(identity) ? [{ identity, text }] : []
    })
    if (pending.length === 0) { yield* next(); return }

    const text = pending.flatMap(message => message.text)
    const identity = createHash('sha256').update(JSON.stringify(pending.map(message => message.identity))).digest('hex')
    const payload = textPayload(text)
    if (consumeIgnoreOnce('deepseek', session, payload)) {
      const clean = removeConsumedCommand(options.messages, new Set(pending.map(message => message.identity)))
      options.messages = clean.messages
      for (const identity of clean.identities) sessionApproved.add(identity)
      approved.set(session, sessionApproved)
      yield* next()
      return
    }
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
      if (degraded.has(result.status)) { options.messages.push(degradedMessage(degradedText(result))); yield* next(); return }
      const notice = result.status === 'approved' ? scanNotice(result.notice) : undefined
      if (notice) options.messages.push(degradedMessage(noticeText(notice)))
      if (result.status !== 'approved') {
        const visible = receipt(result, 'request')
        if (injectionFinding(result) && typeof visible === 'object' && visible !== null && !Array.isArray(visible)) {
          const command = issueIgnoreOnce('deepseek', session, payload)
          if (command) {
            visible.ignore_once = command
            visible.message = 'Injection risk blocked this prompt. Add ignore_once to the same message and resend it within 15 minutes to allow that message once.'
          }
        }
        throw new Error(JSON.stringify(visible))
      }
      for (const message of pending) sessionApproved.add(message.identity)
      approved.set(session, sessionApproved)
      yield* next()
    } catch (error) {
      if (!completed) events.emit({ kind: 'scan_failed', direction: 'request', tool: 'user_prompt', session_id: session, ...(scanId ? { scan_id: scanId } : {}), status: 'failed', duration_ms: elapsed(started), payload_hash: payloadHash })
      if (completed) throw error
      options.messages.push(degradedMessage(degradedText({ reason: scanId ? 'scanner_connection_lost' : 'runtime_start_failed' })))
      yield* next()
    }
  })
}
