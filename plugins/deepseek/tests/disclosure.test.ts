import type { Context } from '@deepseek-ai/cordis'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import ApprovalService, { type ApprovalOutcome } from '@deepseek-ai/dsh-user-approval'
import { afterEach, describe, expect, it } from 'vitest'
import { MockAdapter, textResponse, toolCallResponse } from 'harness-test-mock'
import type { DisclosedParams, DisclosureParams } from '../src/protocol.ts'
import { FakeClient } from './fake-client.ts'
import { createAgent, createHarness, lastReceipt } from './harness.ts'

const SCAN = 'a'.repeat(32)
const GRANT = 'b'.repeat(32)
const EMAIL = 'ada.reveal@example.com'

class DisclosureClient extends FakeClient {
  prepared: DisclosureParams[] = []
  read: DisclosedParams[] = []
  constructor() { super({ async scan() { return { status: 'approved' } } }) }
  async prepareDisclosure(params: DisclosureParams) {
    this.prepared.push(params)
    return { scan_id: params.scan_id, status: 'confirmation_required' as const, grant_id: GRANT, counts: { email: 1 }, expires_in_seconds: 300 }
  }
  async readDisclosed(params: DisclosedParams) {
    this.read.push(params)
    return { scan_id: params.scan_id, status: 'redacted' as const, result: `Contact: ${EMAIL}, phone [REDACTED].`,
      disclosure: { authorized_pii_types: ['email' as const], user_confirmed: true as const, applied: true } }
  }
}

const contexts: Context[] = []
afterEach(async () => { for (const ctx of contexts.splice(0)) await ctx.fiber.dispose() })

async function run(answer?: ApprovalOutcome) {
  const client = new DisclosureClient()
  const adapter = new MockAdapter([
    toolCallResponse('offer', 'patronus_read_redacted', { scan_id: SCAN, reveal_pii: ['email'] }),
    options => {
      const offer = lastReceipt(options.messages) as { status: string; grant_id?: string }
      expect(offer.status).toBe('confirmation_required')
      expect(JSON.stringify(options)).not.toContain(EMAIL)
      return toolCallResponse('reveal', 'patronus_reveal_pii', { scan_id: SCAN, grant_id: offer.grant_id })
    },
    textResponse('done'),
  ])
  const ctx = await createHarness(client, adapter)
  contexts.push(ctx)
  await ctx.plugin(ApprovalService)
  const asked: Array<{ toolName: string; reason?: string }> = []
  if (answer) ctx.on('approval/request', req => { asked.push({ toolName: req.toolName, reason: req.reason }); return Promise.resolve(answer) })
  const agent = await createAgent(ctx)
  agent.followup(createUserMessage({ content: [{ type: 'text', text: 'Reveal the contact email.' }], source: { kind: 'user' } }))
  await agent.whenIdle()
  const results = agent.session.snapshotEvents().filter(event => event.type === 'tool/result')
  return { client, asked, final: JSON.stringify(results.at(-1)), all: JSON.stringify(results) }
}

describe('selective PII disclosure through the Harness approval seam', () => {
  it('asks the user with counts and delivers the view only after allowed-once', async () => {
    const { client, asked, final } = await run('allowed-once')
    expect(client.prepared).toEqual([{ session: expect.any(String), scan_id: SCAN, reveal_pii: ['email'] }])
    expect(asked).toEqual([{ toolName: 'patronus_reveal_pii', reason: expect.stringContaining('Reveal 1 email address') }])
    expect(client.read).toHaveLength(1)
    expect(final).toContain(EMAIL)
    expect(final).toContain('user_confirmed')
  })

  for (const answer of ['rejected', 'cancelled', undefined] as const) {
    it(`keeps the mask when the approval is ${answer ?? 'unavailable'}`, async () => {
      const { client, all } = await run(answer)
      expect(client.read).toHaveLength(0)
      expect(all).not.toContain(EMAIL)
      expect(all).toContain('disclosure_unavailable')
    })
  }
})
