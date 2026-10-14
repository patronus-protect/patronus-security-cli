import { defineTool, type ToolDefinition, type ToolExecution } from '@deepseek-ai/dsh-tools'
import type { Context } from '@deepseek-ai/cordis'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import { PII_TYPES, type PiiType, type RuntimeClient } from './protocol.ts'
import { disclosureQuestion } from './disclosure.ts'
import { receipt, redactedMessage, unavailable } from './receipts.ts'
import { autoRedact } from './auto-redaction.ts'
import type { StaticScanner } from './static.ts'
import { elapsed, hashProtocolValue, type ProtocolEventSink } from './protocol-events.ts'
import { invalidScanReference, unavailableScanReference } from './references.ts'

export function registerTools(ctx: Context, clientFor: (exec: ToolExecution) => Promise<RuntimeClient>, sessionFor: (exec: ToolExecution) => string, scanner: StaticScanner, events: ProtocolEventSink): (exec: ToolExecution) => boolean {
  const ownTools = new Map<string, ToolDefinition>()
  // Disclosure offers of this plugin instance, keyed by grant; a grant ID alone releases nothing.
  const offers = new Map<string, { scanId: string; session: string; counts: Record<string, number> }>()
  const ownExecutions = new WeakSet<ToolExecution>()
  const register = (definition: ToolDefinition) => {
    ownTools.set(definition.name, definition)
    ctx.tools.register(definition)
  }
  register(defineTool({
    name: 'patronus_scan',
    description: 'Run an optional static file, directory, repository, public HTTPS URL or MCP audit only after an explicit user request. Public URL and MCP-server audits currently always use the Patronus Security API. URL scans can use the rate-limited anonymous allowance; MCP-server audits require an authenticated account. Never infer a repository scan from the working directory or an ordinary read. Runtime hooks separately protect text that crosses the prompt/tool/MCP result boundary. Returns bounded security metadata only; never source content or runtime scan IDs.',
    parameters: {
      kind: { type: 'string', enum: ['repo', 'directory', 'file', 'url', 'mcp'], required: true },
      path: { type: 'string', required: true },
      server: { type: 'string' },
    },
    output: { schema: { type: 'json' }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args, exec): Promise<JsonValue> {
      const started = performance.now()
      const session = sessionFor(exec)
      const payloadHash = hashProtocolValue(args)
      events.emit({ kind: 'scan_started', direction: 'static', tool: 'patronus_scan', session_id: session, status: 'pending', payload_hash: payloadHash })
      const result = await scanner.scan(args, exec.signal)
      const status = typeof result === 'object' && result !== null && !Array.isArray(result) && typeof result.status === 'string' ? result.status.toLowerCase() : 'failed'
      events.emit({ kind: 'scan_completed', direction: 'static', tool: 'patronus_scan', session_id: session, status, duration_ms: elapsed(started), payload_hash: payloadHash })
      return result
    },
  }))
  for (const redacted of [false, true]) {
    register(defineTool({
      name: redacted ? 'patronus_read_redacted' : 'patronus_check_result',
      description: redacted
        ? 'Retrieve verified masked text. Pass exactly one reference: scan_id for a completed dangerous runtime response, or file_id from a static file/directory/repository finding. Never returns the original. Only when the task needs specific masked personal data, add reveal_pii with scan_id: this returns counts and a grant_id for patronus_reveal_pii, never values.'
        : 'Retrieve scan status and any approved original or automatically redacted PII/DLP result for a runtime scan_id. Continue the task with status=redacted text.',
      parameters: redacted
        ? { scan_id: { type: 'string' }, file_id: { type: 'string' }, reveal_pii: { type: 'array', items: { type: 'string', enum: PII_TYPES } } }
        : { scan_id: { type: 'string', required: true } },
      output: { schema: { type: 'json' }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
      async execute(args, exec): Promise<JsonValue> {
        const started = performance.now()
        const session = sessionFor(exec)
        const input = args as Record<string, unknown>
        const scan_id = typeof input.scan_id === 'string' ? input.scan_id : undefined
        const file_id = typeof input.file_id === 'string' ? input.file_id : undefined
        const hashInput: Record<string, JsonValue> = {
          ...(scan_id === undefined ? {} : { scan_id }),
          ...(file_id === undefined ? {} : { file_id }),
        }
        const payloadHash = hashProtocolValue(hashInput)
        const complete = (status: string) => events.emit({ kind: 'scan_completed', direction: 'status', tool: redacted ? 'patronus_read_redacted' : 'patronus_check_result', session_id: session, ...(scan_id === undefined ? {} : { scan_id }), status, duration_ms: elapsed(started), payload_hash: payloadHash })
        if (redacted && file_id !== undefined && scan_id === undefined && Object.keys(input).length === 1) {
          const result = await scanner.readRedacted(file_id, exec.signal)
          complete(typeof result === 'object' && result !== null && !Array.isArray(result) && typeof result.status === 'string' ? result.status : 'failed')
          return result
        }
        if (redacted && Object.hasOwn(input, 'reveal_pii')) {
          const types = input.reveal_pii
          if (scan_id === undefined || Object.keys(input).length !== 2 || !Array.isArray(types) || !types.length ||
              !types.every(type => (PII_TYPES as readonly unknown[]).includes(type))) {
            complete('invalid_reference')
            return { status: 'invalid_arguments', required: ['scan_id', 'reveal_pii'], message: 'Pass scan_id and reveal_pii with types from the fixed list.' }
          }
          const invalid = invalidScanReference(scan_id)
          if (invalid) { complete('invalid_reference'); return invalid }
          try {
            const client = await clientFor(exec)
            if (!client.prepareDisclosure) { complete('disclosure_unavailable'); return { scan_id, status: 'disclosure_unavailable' } }
            const offer = await client.prepareDisclosure({ session, scan_id, reveal_pii: [...new Set(types as PiiType[])] }, exec.signal)
            complete(offer.status)
            if (offer.status === 'unavailable') return unavailableScanReference()
            if (offer.status !== 'confirmation_required' || !offer.grant_id || !offer.counts) return { scan_id, status: offer.status }
            for (const [grant, value] of offers) if (value.scanId === scan_id && value.session === session) offers.delete(grant)
            offers.set(offer.grant_id, { scanId: scan_id, session, counts: offer.counts as Record<string, number> })
            return { scan_id, status: 'confirmation_required', grant_id: offer.grant_id, counts: offer.counts as Record<string, number>, next_tool: 'patronus_reveal_pii',
              message: 'Call patronus_reveal_pii once with this scan_id and grant_id. The user is asked to approve; if they deny, continue with the masked result and do not ask again unprompted.' }
          } catch { complete('unavailable'); return receipt(unavailable(scan_id)) }
        }
        if (scan_id === undefined || Object.keys(input).length !== 1) {
          complete('invalid_reference')
          return { status: 'invalid_reference', code: 'invalid_arguments', expected: redacted ? 'exactly_one_of_scan_id_or_file_id' : 'runtime_scan_id', message: redacted ? 'Pass exactly one reference: scan_id or file_id.' : 'Pass one runtime scan_id.' }
        }
        const invalid = invalidScanReference(scan_id)
        if (invalid) { complete('invalid_reference'); return invalid }
        try {
          const client = await clientFor(exec)
          const job = { session, scan_id }
          if (redacted) {
            const result = await client.readRedacted(job, exec.signal)
            complete(result.status)
            return result.status === 'redacted' && result.result !== undefined
              ? { scan_id, status: 'redacted', result: result.result, message: redactedMessage }
              : unavailableScanReference()
          }
          const result = await autoRedact(await client.check(job, exec.signal), () => client.readRedacted(job, exec.signal))
          complete(result.status)
          if (result.status === 'unavailable') return unavailableScanReference()
          // Never reflect a payload merely because a transport included a result field.
          return result.status === 'approved' && result.result !== undefined
            ? { ...receipt(result) as Record<string, JsonValue>, result: result.result }
            : receipt(result)
        } catch { complete('unavailable'); return receipt(unavailable(scan_id)) }
      },
    }))
  }
  register(defineTool({
    name: 'patronus_reveal_pii',
    description: 'Ask the user to approve a one-time disclosure offered by patronus_read_redacted with reveal_pii. Harness asks the user; only an approved call returns the result with the confirmed PII types visible. If the user denies, continue with the masked result.',
    parameters: { scan_id: { type: 'string', required: true }, grant_id: { type: 'string', required: true } },
    output: { schema: { type: 'json' }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
    async execute(args, exec): Promise<JsonValue> {
      const started = performance.now()
      const session = sessionFor(exec)
      const input = args as Record<string, unknown>
      const scan_id = typeof input.scan_id === 'string' ? input.scan_id : ''
      const grant_id = typeof input.grant_id === 'string' ? input.grant_id : ''
      const complete = (status: string) => events.emit({ kind: 'scan_completed', direction: 'status', tool: 'patronus_reveal_pii', session_id: session, scan_id, status, duration_ms: elapsed(started), payload_hash: hashProtocolValue({ scan_id, grant_id }) })
      const unavailableDisclosure = (message: string): JsonValue => { complete('disclosure_unavailable'); return { scan_id, status: 'disclosure_unavailable', message } }
      if (Object.keys(input).length !== 2 || !/^[a-f0-9]{32}$/.test(scan_id) || !/^[a-f0-9]{32}$/.test(grant_id)) {
        return { status: 'invalid_arguments', required: ['scan_id', 'grant_id'], message: 'Pass the scan_id and grant_id from the disclosure offer.' }
      }
      const offer = offers.get(grant_id)
      const question = offer && offer.scanId === scan_id && offer.session === session ? disclosureQuestion(offer.counts) : undefined
      if (!offer || !question) return unavailableDisclosure('This disclosure offer is no longer available. Continue with the masked result.')
      // The Harness approval seam answers for a human; without an answerer it fails closed.
      const approval = (ctx as unknown as { get(name: 'approval'): { request(req: object): Promise<string> } | undefined }).get('approval')
      if (!approval || !exec.agent) return unavailableDisclosure('PII disclosure needs the user to approve it, and no approval channel is available. Continue with the masked result.')
      const outcome = await approval.request({ agent: exec.agent, toolName: 'patronus_reveal_pii', callId: exec.callId, reason: question, signal: exec.signal })
      offers.delete(grant_id)
      if (outcome !== 'allowed-once') return unavailableDisclosure('The user did not approve this disclosure. Continue with the masked result.')
      try {
        const client = await clientFor(exec)
        if (!client.readDisclosed) return unavailableDisclosure('This runtime cannot deliver disclosures. Continue with the masked result.')
        const result = await client.readDisclosed({ session, scan_id, grant_id }, exec.signal)
        complete(result.status)
        if (result.status === 'unavailable') return unavailableScanReference()
        return result.status === 'redacted' && result.result !== undefined && result.disclosure
          ? { scan_id, status: 'redacted', result: result.result, disclosure: result.disclosure as unknown as JsonValue }
          : { scan_id, status: result.status }
      } catch { complete('unavailable'); return receipt(unavailable(scan_id)) }
    },
  }))
  return exec => {
    if (ownExecutions.has(exec)) return true
    const own = ownTools.has(exec.name) && ctx.tools.get(exec.name, exec.agent) === ownTools.get(exec.name)
    // Preserve the verified origin on the execution itself. Results may arrive
    // after the registry changed; a same-named foreign definition is not own.
    if (own) ownExecutions.add(exec)
    return own
  }
}
