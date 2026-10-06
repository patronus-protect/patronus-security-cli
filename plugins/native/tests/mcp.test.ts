import assert from 'node:assert/strict'
import test from 'node:test'
import { handleMcp } from '../src/mcp.ts'

test('Codex MCP exposes scan/status/redacted tools and a navigation view without session credentials', async () => {
  const response: any = await handleMcp({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
  assert.deepEqual(response.result.tools.map((tool: any) => tool.name), ['patronus_check_result', 'patronus_read_redacted', 'patronus_scan', 'patronus_open_home'])
  for (const tool of response.result.tools) {
    assert.equal(tool.inputSchema.additionalProperties, false)
    assert(!JSON.stringify(tool.inputSchema).includes('session'))
    assert(!JSON.stringify(tool.inputSchema).includes('capability'))
  }
  const redacted = response.result.tools.find((tool: any) => tool.name === 'patronus_read_redacted')
  assert.equal(redacted.inputSchema.required, undefined)
  const scan = response.result.tools.find((tool: any) => tool.name === 'patronus_scan')
  assert.match(scan.description, /URL and MCP-server audits currently always use the Patronus Security API/)
})

test('Codex home entrypoints resolve to a packaged MCP Apps resource without invoking the scanner', async () => {
  const list: any = await handleMcp({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
  const tool = list.result.tools.find((value: any) => value.name === 'patronus_open_home')
  assert.deepEqual(tool._meta['openai/ui'].entrypoints, [{ type: 'global' }, { type: 'thread' }])
  const resource: any = await handleMcp({ jsonrpc: '2.0', id: 2, method: 'resources/read', params: { uri: tool._meta.ui.resourceUri } })
  assert.equal(resource.result.contents[0].mimeType, 'text/html;profile=mcp-app')
  assert.match(resource.result.contents[0].text, /Protection status has not been checked/)
  const call: any = await handleMcp({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: tool.name, arguments: {} } })
  assert.match(call.result.content[0].text, /Protection status has not been checked/)
  const invalid: any = await handleMcp({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: tool.name, arguments: { path: '/private/canary' } } })
  assert.equal(invalid.error.code, -32602)
  assert(!JSON.stringify(invalid).includes('/private/canary'))
  const missing: any = await handleMcp({ jsonrpc: '2.0', id: 5, method: 'resources/read', params: { uri: 'file:///private/canary' } })
  assert.equal(missing.error.code, -32602)
})

test('missing native hook never releases data or reflects arguments', async () => {
  const response: any = await handleMcp({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'patronus_read_redacted', arguments: { scan_id: 'PRIVATE-CANARY', path: '/private/file' } } })
  assert.equal(response.result.isError, true)
  assert(!JSON.stringify(response).includes('PRIVATE-CANARY'))
  assert(!JSON.stringify(response).includes('/private/file'))
})

test('failed static audit fallback is degraded but does not block continuation', async () => {
  const response: any = await handleMcp({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'patronus_scan', arguments: { kind: 'url', path: 'https://example.org/' } } })
  assert.equal(response.result.isError, false)
  assert.match(response.result.content[0].text, /protection is degraded/)
  assert(!JSON.stringify(response).includes('https://example.org/'))
})
