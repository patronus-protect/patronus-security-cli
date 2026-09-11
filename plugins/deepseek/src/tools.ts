import { defineTool, type ToolDefinition, type ToolExecution } from '@deepseek-ai/dsh-tools'
import type { Context } from '@deepseek-ai/cordis'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import type { RuntimeClient } from './protocol.ts'
import { receipt, unavailable } from './receipts.ts'
import { autoRedact } from './auto-redaction.ts'
import type { StaticScanner } from './static.ts'
import { elapsed, hashProtocolValue, type ProtocolEventSink } from './protocol-events.ts'
import { invalidScanReference, unavailableScanReference } from './references.ts'

export function registerTools(ctx: Context, clientFor: (exec: ToolExecution) => Promise<RuntimeClient>, sessionFor: (exec: ToolExecution) => string, scanner: StaticScanner, events: ProtocolEventSink): (exec: ToolExecution) => boolean {
  const ownTools = new Map<string, ToolDefinition>()
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
        ? 'Retrieve verified masked text. Pass exactly one reference: scan_id for a completed dangerous runtime response, or file_id from a static file/directory/repository finding. Never returns the original.'
        : 'Retrieve scan status and any approved original or automatically redacted PII/DLP result for a runtime scan_id. Continue the task with status=redacted text.',
      parameters: redacted
        ? { scan_id: { type: 'string' }, file_id: { type: 'string' } }
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
              ? { scan_id, status: 'redacted', result: result.result }
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
  return exec => {
    if (ownExecutions.has(exec)) return true
    const own = ownTools.has(exec.name) && ctx.tools.get(exec.name, exec.agent) === ownTools.get(exec.name)
    // Preserve the verified origin on the execution itself. Results may arrive
    // after the registry changed; a same-named foreign definition is not own.
    if (own) ownExecutions.add(exec)
    return own
  }
}
