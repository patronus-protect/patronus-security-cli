// Only the model and document tool are scripted. The host, plugin and scanner are real.
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, appendFileSync } from 'node:fs'
import { setTimeout as delay } from 'node:timers/promises'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { LlmAdapter } from '@deepseek-ai/dsh-llm'
const { textResponse, toolCallResponse } = await import(process.env.PATRONUS_E2E_MOCK_HELPERS)
export const name = 'release-model'
export const inject = ['llm', 'tools']
export function apply(ctx, config) {
  let receipt, remoteReport, calls = 0, reads = 0
  const states = [], tools = [], requests = []
  ctx.tools.register(defineTool({
    name: 'release_read_document', description: 'Read the local release fixture document.', parameters: {},
    output: { schema: { type: 'string' }, render: (_args, text) => [{ type: 'text', text }] },
    execute() {
      reads++; appendFileSync(config.counter, '1')
      return readFileSync(config.flow === 'queue-backlog' && reads === 1 ? config.blocker : config.document, 'utf8')
    },
  }))
  const visit = value => {
    if (!value || typeof value !== 'object') return
    if (value.type === 'text') {
      try { const data = JSON.parse(value.text); if (typeof data.status === 'string' && typeof data.scan_id === 'string') receipt = data } catch {}
    }
    for (const child of Object.values(value)) visit(child)
  }
  ctx.on('tools/result', (exec, result) => {
    if (exec.name === 'patronus_scan') remoteReport = result.value
    if (exec.name === 'release_read_document' || exec.name.startsWith('patronus_')) visit(result)
  })
  class ScriptedModel extends LlmAdapter {
    async resolveModel(provider, model) { return { provider, id: model, name: model } }
    async *stream(options) {
      requests.push(options.messages)
      writeFileSync(config.requests, JSON.stringify(requests))
      const visible = JSON.stringify(options.messages)
      assert(!visible.includes('release.author@example.com'), 'Original PII reached the model')
      assert(!visible.includes('IGNORE ALL PREVIOUS INSTRUCTIONS'), 'Original injection reached the model')
      assert(!visible.includes('Patronus native hooks did not handle this call'), 'Retrieval reached placeholder')
      assert(++calls <= 120, 'Too many model calls')
      if (config.degraded) {
        assert(visible.includes('No security scan was completed'), 'Inactive Patronus warning did not reach the model')
        if (calls === 1) {
          tools.push('degraded-source')
          yield* toolCallResponse('read', 'release_read_document', {}); return
        }
        assert(visible.includes('RELEASE_DOCUMENT_731'), 'Original unscanned result did not remain available')
        assert.equal(reads, 1)
        writeFileSync(config.evidence, JSON.stringify({ states: ['degraded'], tools, sourceExecutions: reads, modelCalls: calls, completed: true, degradedWarning: true, originalAvailable: true }))
        yield* textResponse('RELEASE_FLOW_PASSED'); return
      }
      if (calls === 1 && config.flow === 'remote-fail-open') {
        tools.push('patronus_scan')
        yield* toolCallResponse('remote-audit', 'patronus_scan', { kind: 'url', path: 'https://example.org/' }); return
      }
      if (config.flow === 'remote-fail-open' && reads === 0) {
        assert.equal(remoteReport?.status, 'FAILED', 'Unavailable API audit did not expose its failed scan result')
        assert(visible.includes('Patronus protection is inactive'), 'Unavailable API audit omitted degraded context')
        tools.push('source'); yield* toolCallResponse('read', 'release_read_document', {}); return
      }
      if (calls === 1) { tools.push('source'); yield* toolCallResponse('read', 'release_read_document', {}); return }
      if (config.flow === 'queue-backlog' && reads === 1) {
        tools.push('queue-blocker')
        yield* toolCallResponse('queued-read', 'release_read_document', {}); return
      }
      if (config.flow === 'read-redacted') {
        receipt = undefined
        visit(options.messages)
      }
      assert(receipt, 'No scan receipt reached the model')
      // Do not accept an event-only receipt: its scan id must actually be visible.
      assert(visible.includes(receipt.scan_id), 'Receipt missing from model input')
      states.push(receipt.status)
      if (receipt.status === 'pending') {
        assert(!visible.includes('RELEASE_DOCUMENT_731'), 'Original content reached the model before approval')
        if (config.flow === 'queue-backlog') {
          assert.equal(receipt.job_status, 'queued')
          assert.equal(receipt.wait_reason, 'scanner_queue')
          assert.equal(receipt.next_tool, 'patronus_check_result')
          assert.match(receipt.message, /not a scan failure or expiry/)
        }
        tools.push('patronus_check_result'); await delay(30)
        yield* toolCallResponse('check-' + calls, 'patronus_check_result', { scan_id: receipt.scan_id }); return
      }
      if (receipt.status === 'dangerous' && config.flow === 'read-redacted') {
        tools.push('patronus_read_redacted')
        yield* toolCallResponse('redact-' + calls, 'patronus_read_redacted', { scan_id: receipt.scan_id }); return
      }
      assert.equal(receipt.status, ['auto-pii','read-redacted'].includes(config.flow) ? 'redacted' : 'approved')
      {
        assert(visible.includes('RELEASE_DOCUMENT_731'), 'Expected document missing from model input')
        assert(visible.includes('0.1.0'), 'Version missing from model input')
      }
      if (['auto-pii','read-redacted'].includes(config.flow)) assert(visible.includes('[REDACTED]'))
      if (config.flow === 'pending') assert(states.includes('pending') && tools.includes('patronus_check_result'))
      if (config.flow === 'read-redacted') {
        assert(states.includes('dangerous'))
        assert(tools.includes('patronus_read_redacted'))
        assert.equal(receipt.result, config.expectedRedacted, 'Redaction must change only the injection span')
      }
      assert.equal(reads, config.flow === 'queue-backlog' ? 2 : 1)
      writeFileSync(config.evidence, JSON.stringify({ ...(config.flow === 'queue-backlog' ? { queueBackpressureVisible: true } : {}), ...(config.flow === 'read-redacted' ? { exactRedaction: true, unchangedSurroundingContent: true } : {}), ...(config.flow === 'remote-fail-open' ? { remoteAudit: 'FAILED', degraded: true, failOpen: true } : {}), states, tools, sourceExecutions: reads, modelCalls: calls, completed: true }))
      yield* textResponse('RELEASE_FLOW_PASSED')
    }
  }
  ctx.llm.registerAdapter(['release-model'], new ScriptedModel())
}
