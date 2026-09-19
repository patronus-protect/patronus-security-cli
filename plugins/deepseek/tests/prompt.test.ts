import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import { MockAdapter, textResponse } from 'harness-test-mock'
import { describe, expect, it } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { issueIgnoreOnce } from '../src/ignore-once.ts'
import { FakeClient } from './fake-client.ts'
import { createHarness } from './harness.ts'

async function consume(stream: AsyncIterable<unknown>): Promise<void> {
  for await (const _chunk of stream) { /* consume the host stream */ }
}

describe('user prompt gate', () => {
  it('accepts a matching one-time retry without scanning it again', async () => {
    const root = await mkdtemp(join(tmpdir(), 'patronus-deepseek-ignore-'))
    const previous = process.env.PATRONUS_DATA_DIR
    process.env.PATRONUS_DATA_DIR = root
    const client = new FakeClient({ async scan() { return { status: 'dangerous' } } })
    const adapter = new MockAdapter([textResponse('done')])
    const ctx = await createHarness(client, adapter)
    try {
      const session = 'prompt-ignore-once'
      const token = issueIgnoreOnce('deepseek', session, 'blocked prompt')
      const message = createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: `blocked prompt ${token}` }] })
      await consume(ctx.llm.stream({ provider: 'probe', model: 'scripted', sessionId: SessionId(session), messages: [message] }))
      expect(adapter.requests).toHaveLength(1)
      expect(JSON.stringify(adapter.requests[0])).not.toContain('ignore_once')
      expect(client.submissions).toHaveLength(0)
      await expect(consume(ctx.llm.stream({ provider: 'probe', model: 'scripted', sessionId: SessionId(session), messages: [
        createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: `blocked prompt ${token}` }] }),
      ] }))).rejects.toThrow('dangerous')
      expect(client.submissions).toHaveLength(1)
    } finally {
      await ctx.fiber.dispose()
      if (previous === undefined) delete process.env.PATRONUS_DATA_DIR
      else process.env.PATRONUS_DATA_DIR = previous
      await rm(root, { recursive: true, force: true })
    }
  })

  it('submits only ordered user text blocks when the prompt also contains media', async () => {
    const client = new FakeClient({ async scan() { return { status: 'approved' } } })
    const adapter = new MockAdapter([textResponse('done')])
    const ctx = await createHarness(client, adapter)
    try {
      const message = createUserMessage({
        source: { kind: 'user' },
        content: [
          { type: 'text', text: 'first prompt block' },
          { type: 'image', attachment: { attachmentId: 'image', mediaType: 'image/png', bytes: 1 } } as never,
          { type: 'text', text: '{"raw":"prompt JSON"}' },
        ],
      })
      await consume(ctx.llm.stream({
        provider: 'probe', model: 'scripted', sessionId: SessionId('prompt-mixed-media'), messages: [message],
      }))

      expect(adapter.requests).toHaveLength(1)
      expect(client.submissions).toHaveLength(1)
      expect(client.submissions[0]).toMatchObject({
        direction: 'request', tool: 'user_prompt', payload: ['first prompt block', '{"raw":"prompt JSON"}'],
      })
      expect(JSON.stringify(client.submissions)).not.toContain('attachmentId')
    } finally { await ctx.fiber.dispose() }
  })

  it('does not call the model when user text is dangerous', async () => {
    const client = new FakeClient({ async scan() { return { status: 'dangerous' } } })
    const adapter = new MockAdapter([textResponse('must not run')])
    const ctx = await createHarness(client, adapter)
    try {
      const message = createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: 'dangerous user text' }] })
      await expect(consume(ctx.llm.stream({
        provider: 'probe', model: 'scripted', sessionId: SessionId('prompt-dangerous'), messages: [message],
      }))).rejects.toThrow('dangerous')
      expect(adapter.requests).toHaveLength(0)
      expect(client.submissions[0]?.payload).toBe('dangerous user text')
    } finally { await ctx.fiber.dispose() }
  })

  it('scans an approved user message once across later model turns', async () => {
    const client = new FakeClient({ async scan() { return { status: 'approved' } } })
    const adapter = new MockAdapter([textResponse('one'), textResponse('two')])
    const ctx = await createHarness(client, adapter)
    try {
      const message = createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: 'same prompt' }] })
      const options = { provider: 'probe', model: 'scripted', sessionId: SessionId('prompt-repeat'), messages: [message] }
      await consume(ctx.llm.stream(options))
      await consume(ctx.llm.stream(options))
      expect(client.submissions.map(item => item.payload)).toEqual(['same prompt'])
    } finally { await ctx.fiber.dispose() }
  })
})
