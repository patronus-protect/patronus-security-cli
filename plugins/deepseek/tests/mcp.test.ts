import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { syncTools } from 'harness-mcp-bridge'
import { MockAdapter, textResponse, toolCallResponse } from 'harness-test-mock'
import { expect, it } from 'vitest'
import { ControlledScanner, createAgent, createHarness, lastReceipt } from './harness.ts'

it('holds a real MCP SDK result through the Harness bridge and lets the agent retrieve it after approval', async () => {
  const canary = `mcp-original-${crypto.randomUUID()}`
  const jsonText = '{"raw":"MCP JSON text"}'
  const scanner = new ControlledScanner(canary)
  let sourceCalls = 0
  let id = ''
  const adapter = new MockAdapter([
    toolCallResponse('mcp-source', 'mcp__probe__document', {}),
    options => {
      const receipt = lastReceipt(options.messages)
      expect(receipt.status).toBe('pending')
      expect(JSON.stringify(options)).not.toContain(canary)
      id = receipt.scan_id
      return toolCallResponse('pending-check', 'patronus_check_result', { scan_id: id })
    },
    options => {
      expect(lastReceipt(options.messages).status).toBe('pending')
      scanner.complete({ status: 'approved' })
      return toolCallResponse('approved-check', 'patronus_check_result', { scan_id: id })
    },
    options => {
      expect(lastReceipt(options.messages).status).toBe('approved')
      expect(JSON.stringify(options)).toContain(canary)
      return textResponse('Retrieved the approved MCP document.')
    },
  ])
  const ctx = await createHarness(scanner, adapter, { responseWaitMs: 0 })
  const server = new McpServer({ name: 'patronus-probe', version: '0.0.0' })
  const client = new Client({ name: 'patronus-probe', version: '0.0.0' })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const disposers = new Map<string, () => void>()
  try {
    server.registerTool('document', { description: 'Read the synthetic document.', inputSchema: {} }, async () => {
      sourceCalls++
      return {
        content: [
          { type: 'text', text: canary },
          { type: 'image', data: 'AA==', mimeType: 'image/png' },
          { type: 'text', text: jsonText },
        ],
        structuredContent: { document: canary },
      }
    })
    await server.connect(serverTransport)
    await client.connect(clientTransport)
    for (const [key, dispose] of await syncTools(client, ctx, {
      serverName: 'probe', toolCallTimeoutMs: 1000, registrationFailure: 'throw',
    }, new Map())) disposers.set(key, dispose)
    const agent = await createAgent(ctx, 'mcp-agent')
    agent.followup(createUserMessage({ content: [{ type: 'text', text: 'Read the MCP document and check its scan status.' }], source: { kind: 'user' } }))
    await agent.whenIdle()

    expect(adapter.requests).toHaveLength(4)
    expect(sourceCalls).toBe(1)
    expect(scanner.submissions).toHaveLength(2)
    expect(scanner.submissions[0]).toBe('Read the MCP document and check its scan status.')
    expect(scanner.submissions[1]).toEqual([canary, jsonText,
      `${canary}\n[image unavailable: image/png; this result was not admitted to durable model context; raw image data remains available to programmatic callers]\n${jsonText}`,
    ])
    expect(JSON.stringify(scanner.submissions)).not.toContain('structuredContent')
    const results = agent.session.snapshotEvents().filter(event => event.type === 'tool/result')
    expect(JSON.stringify(results.slice(0, 2))).not.toContain(canary)
    expect(JSON.stringify(results[2])).toContain(canary)
    expect(JSON.stringify(agent.session.snapshotEvents())).toContain('Retrieved the approved MCP document.')
  } finally {
    for (const dispose of disposers.values()) dispose()
    await client.close()
    await server.close()
    await ctx.fiber.dispose()
  }
})
