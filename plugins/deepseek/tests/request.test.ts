import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { MockAdapter, toolCallResponse } from 'harness-test-mock'
import { describe, expect, it } from 'vitest'
import { LocalClient } from '../src/client.ts'
import { receipt, unavailable } from '../src/receipts.ts'
import { FakeClient } from './fake-client.ts'
import { createAgent, createHarness, execute, registerTextTool } from './harness.ts'

describe('external-text boundary', () => {
  it('does not scan tool requests', async () => {
    const client = new FakeClient({ async scan() { return { status: 'approved' } } })
    const ctx = await createHarness(client)
    let calls = 0
    try {
      registerTextTool(ctx, 'side_effect', 'external result', () => { calls++ })
      const result = await execute(ctx, 'side_effect', { command: 'request text is out of scope' })
      expect(calls).toBe(1)
      expect(result.isError).toBe(false)
      expect(client.submissions).toHaveLength(1)
      expect(client.submissions[0]).toMatchObject({ direction: 'response', payload: 'external result' })
      expect(JSON.stringify(client.submissions)).not.toContain('request text is out of scope')
    } finally { await ctx.fiber.dispose() }
  })

  it('scans every result text block beside media and no wrapper data', async () => {
    const client = new FakeClient({ async scan() { return { status: 'approved' } } })
    const ctx = await createHarness(client)
    const content = [
      { type: 'text', text: 'caption' },
      { type: 'image', attachment: { attachmentId: 'sha256:image', mediaType: 'image/png', bytes: 1 } },
      { type: 'text', text: '{"raw":"json"}' },
    ]
    try {
      ctx.tools.register(defineTool({
        name: 'media', description: 'media fixture', parameters: {},
        output: { schema: { type: 'string' }, render: () => content as never },
        async execute() { return 'opaque-media-reference' },
      }))
      const result = await execute(ctx, 'media')
      expect(result.content).toEqual(content)
      expect(result.isError).toBe(false)
      expect(client.submissions).toHaveLength(1)
      expect(client.submissions[0]).toMatchObject({ direction: 'response', payload: ['caption', '{"raw":"json"}'] })
      expect(JSON.stringify(client.submissions)).not.toContain('opaque-media-reference')
    } finally { await ctx.fiber.dispose() }
  })

  it('does not scan media-only results', async () => {
    const client = new FakeClient({ async scan() { return { status: 'approved' } } })
    const ctx = await createHarness(client)
    try {
      ctx.tools.register(defineTool({
        name: 'media-only', description: 'media fixture', parameters: {},
        output: { schema: { type: 'string' }, render: () => [{ type: 'image', attachment: { attachmentId: 'sha256:image', mediaType: 'image/png', bytes: 1 } }] as never },
        async execute() { return 'opaque-media-reference' },
      }))
      expect((await execute(ctx, 'media-only')).isError).toBe(false)
      expect(client.submissions).toEqual([])
    } finally { await ctx.fiber.dispose() }
  })

  it('scans a visible projection even when the raw MCP value has no text', async () => {
    const client = new FakeClient({ async scan() { return { status: 'approved' } } })
    const ctx = await createHarness(client)
    try {
      ctx.tools.register(defineTool({
        name: 'projected', description: 'projection fixture', parameters: {},
        output: { schema: { type: 'json' }, render: () => [{ type: 'text', text: 'visible result' }] },
        async execute() { return { content: [] } },
      }))
      expect((await execute(ctx, 'projected')).isError).toBe(false)
      expect(client.submissions).toHaveLength(1)
      expect(client.submissions[0].payload).toBe('visible result')
    } finally { await ctx.fiber.dispose() }
  })

  it('quarantines text inserted after a media-only result was inspected', async () => {
    const client = new FakeClient({ async scan() { return { status: 'approved' } } })
    const adapter = new MockAdapter([toolCallResponse('source', 'late-text', {})])
    const ctx = await createHarness(client, adapter)
    const agent = await createAgent(ctx, 'late-text')
    try {
      const tool = defineTool({
        name: 'late-text', description: 'late text fixture', parameters: {},
        output: { schema: { type: 'string' }, render: () => [] },
        async execute() { return 'opaque' },
      })
      tool.finalizeContent = () => [{ type: 'text', text: 'unscanned late text' }]
      ctx.tools.register(tool)
      agent.followup(createUserMessage({ content: [{ type: 'text', text: 'Run the fixture.' }], source: { kind: 'user' } }))
      await agent.whenIdle()
      expect(adapter.requests).toHaveLength(1)
      expect(JSON.stringify(adapter.requests)).not.toContain('unscanned late text')
      expect(JSON.stringify(agent.session.snapshotEvents())).toContain('unscanned late text')
      expect(client.submissions.map(item => item.payload)).toEqual(['Run the fixture.'])
    } finally { await ctx.fiber.dispose() }
  })
})

describe('Patronus recursion protection', () => {
  it('retains verified Patronus origin when its registry entry changes during execution', async () => {
    const client = new FakeClient({ async scan() { return { status: 'approved' } } })
    const ctx = await createHarness(client)
    const agent = await createAgent(ctx, 'obsolete-patronus-tool')
    const originalCheck = client.check.bind(client)
    client.check = async params => {
      agent.ctx.tools.register(defineTool({
        name: 'patronus_check_result', description: 'foreign replacement', parameters: {},
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: String(value) }] },
        async execute() { return 'foreign' },
      }))
      return originalCheck(params)
    }
    try {
      await execute(ctx, 'patronus_check_result', { scan_id: 'obsolete-result' }, agent)
      expect(client.submissions).toEqual([])
    } finally { await ctx.fiber.dispose() }
  })
})

async function delayedScanner(delayMs: number) {
  const root = await mkdtemp(join(tmpdir(), 'patronus-delayed-startup-'))
  const executable = join(root, 'scanner.mjs')
  await writeFile(executable, `#!${process.execPath}
import readline from 'node:readline'
readline.createInterface({ input: process.stdin }).on('line', line => {
  const request = JSON.parse(line)
  if (request.method !== 'hello') return
  setTimeout(() => process.stdout.write(JSON.stringify({ id: request.id, result: {
    protocol_version: 1, provider: 'local', scanner_version: 'fixture', ark_version: '0.1.6', ready: true,
    runtime: { response_wait_ms: 500, request_timeout_ms: 30000, scan_timeout_ms: 60000, max_payload_bytes: 10485760 }
  } }) + '\\n'), ${delayMs})
})
`, { mode: 0o700 })
  return { root, executable }
}

describe('local model startup budget', () => {
  it('honors the configured startup window independently of ordinary RPC timeouts', async () => {
    const fixture = await delayedScanner(80)
    const short = new LocalClient({ executable: fixture.executable, stateDir: join(fixture.root, 'short'), startupTimeoutMs: 20 })
    const long = new LocalClient({ executable: fixture.executable, stateDir: join(fixture.root, 'long'), startupTimeoutMs: 5_000 })
    try {
      await expect(short.hello()).rejects.toThrow('unavailable')
      await expect(long.hello()).resolves.toMatchObject({ ready: true, ark_version: '0.1.6' })
    } finally {
      await Promise.all([short.close(), long.close()])
      await rm(fixture.root, { recursive: true, force: true })
    }
  })

  it.each([0, 900_001, 1.5])('rejects invalid startupTimeoutMs %s', startupTimeoutMs => {
    expect(() => new LocalClient({ executable: '/missing', stateDir: '/private/tmp/patronus-invalid-startup', startupTimeoutMs })).toThrow('startupTimeoutMs')
  })
})

describe('inactive integration recovery receipt', () => {
  it.each(['request', 'response'] as const)('gives exact recovery commands for unavailable %s scans', direction => {
    expect(receipt(unavailable('scan'), direction, 'custom-profile')).toMatchObject({
      status: 'unavailable',
      recovery: {
        status: 'patronus-security-scanner integration deepseek status --profile custom-profile --format json',
        enable: 'patronus-security-scanner integration deepseek enable --profile custom-profile',
        disable: 'patronus-security-scanner integration deepseek disable --profile custom-profile',
        uninstall: 'patronus-security-scanner integration deepseek uninstall --profile custom-profile',
      },
    })
  })

  it.each(['dangerous', 'failed', 'incomplete'] as const)('does not attach inactive guidance to %s verdicts', status => {
    expect(receipt({ scan_id: 'scan', status })).not.toHaveProperty('recovery')
  })
})
