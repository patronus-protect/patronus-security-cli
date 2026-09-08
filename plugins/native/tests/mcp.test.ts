import assert from 'node:assert/strict'
import test from 'node:test'
import { handleMcp } from '../src/mcp.ts'

test('MCP exposes only scan/status/redacted tools without model-supplied session credentials', () => {
  const response: any = handleMcp({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
  assert.deepEqual(response.result.tools.map((tool: any) => tool.name), ['patronus_check_result', 'patronus_read_redacted', 'patronus_scan'])
  for (const tool of response.result.tools) {
    assert.equal(tool.inputSchema.additionalProperties, false)
    assert(!JSON.stringify(tool.inputSchema).includes('session'))
    assert(!JSON.stringify(tool.inputSchema).includes('capability'))
  }
})

test('missing native hook never releases data or reflects arguments', () => {
  const response: any = handleMcp({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'patronus_read_redacted', arguments: { scan_id: 'PRIVATE-CANARY', path: '/private/file' } } })
  assert.equal(response.result.isError, true)
  assert(!JSON.stringify(response).includes('PRIVATE-CANARY'))
  assert(!JSON.stringify(response).includes('/private/file'))
})
