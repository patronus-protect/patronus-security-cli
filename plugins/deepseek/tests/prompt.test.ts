import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import { MockAdapter, textResponse } from 'harness-test-mock'
import { describe, expect, it } from 'vitest'
import { FakeClient } from './fake-client.ts'
import { createHarness } from './harness.ts'

async function consume(stream: AsyncIterable<unknown>): Promise<void> {
  for await (const _chunk of stream) { /* consume the host stream */ }
}

describe('user prompt gate', () => {
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
