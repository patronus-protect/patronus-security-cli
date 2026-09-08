import { writeFile } from 'node:fs/promises'
import { setTimeout as delay } from 'node:timers/promises'
import type { Context } from '@deepseek-ai/cordis'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { afterEach, describe, expect, it } from 'vitest'
import { MockAdapter, textResponse, toolCallResponse } from 'harness-test-mock'
import { ControlledScanner, createAgent, createHarness, execute, lastReceipt, registerTextTool } from './harness.ts'

const contexts: Context[] = []
afterEach(async () => {
  for (const ctx of contexts.splice(0)) await ctx.fiber.dispose()
})
const own = (ctx: Context) => { contexts.push(ctx); return ctx }

describe('native Harness pending response', () => {
  it('runs independent work, polls twice and releases the original only after approval through the real agent loop', async () => {
    const canary = `withheld-${crypto.randomUUID()}`
    const scanner = new ControlledScanner(canary)
    let id = ''
    let sourceCalls = 0
    let toolStarted = 0
    let receiptLatency = 0
    const adapter = new MockAdapter([
      toolCallResponse('source', 'fetch_document', {}),
      options => {
        receiptLatency = performance.now() - toolStarted
        expect(JSON.stringify(options)).not.toContain(canary)
        const receipt = lastReceipt(options.messages)
        expect(receipt.status).toBe('pending')
        id = receipt.scan_id
        return toolCallResponse('work', 'independent_work', {})
      },
      options => {
        expect(JSON.stringify(options)).toContain('independent-work-complete')
        expect(JSON.stringify(options)).not.toContain(canary)
        return toolCallResponse('poll-1', 'patronus_check_result', { scan_id: id })
      },
      options => {
        expect(lastReceipt(options.messages)).toMatchObject({ status: 'pending', scan_id: id })
        expect(JSON.stringify(options)).not.toContain(canary)
        scanner.complete({ status: 'approved' })
        return toolCallResponse('poll-2', 'patronus_check_result', { scan_id: id })
      },
      options => {
        expect(lastReceipt(options.messages).status).toBe('approved')
        expect(JSON.stringify(options)).toContain(canary)
        return textResponse('Received the approved result after completing independent work.')
      },
    ])
    const ctx = own(await createHarness(scanner, adapter))
    registerTextTool(ctx, 'fetch_document', canary, () => { sourceCalls++; toolStarted = performance.now() })
    registerTextTool(ctx, 'independent_work', 'independent-work-complete')
    const agent = await createAgent(ctx)
    agent.followup(createUserMessage({ content: [{ type: 'text', text: 'Read the test document and report its exact identifier. Also obtain and report the independent calculation result.' }], source: { kind: 'user' } }))
    await agent.whenIdle()

    const events = agent.session.snapshotEvents()
    const calls = events.filter(event => event.type === 'tool/call').map(event => event.data.name)
    expect(calls).toEqual(['fetch_document', 'independent_work', 'patronus_check_result', 'patronus_check_result'])
    expect(adapter.requests).toHaveLength(5)
    expect(sourceCalls).toBe(1)
    expect(scanner.submissions).toHaveLength(3) // User prompt plus two external results; retrieval calls bypass scanning.
    expect(scanner.submissions).toEqual([
      'Read the test document and report its exact identifier. Also obtain and report the independent calculation result.',
      canary,
      'independent-work-complete',
    ])
    expect(receiptLatency).toBeGreaterThanOrEqual(480)
    expect(receiptLatency).toBeLessThan(2000)
    const results = events.filter(event => event.type === 'tool/result')
    expect(JSON.stringify(results.slice(0, 3))).not.toContain(canary)
    expect(JSON.stringify(results[3])).toContain(canary)
    expect(JSON.stringify(events)).toContain('Received the approved result after completing independent work.')
    expect((await ctx.skills.list()).some(skill => skill.name === 'patronus-security')).toBe(true)

    if (process.env.PATRONUS_PROBE_REPORT) {
      await writeFile(process.env.PATRONUS_PROBE_REPORT, JSON.stringify({
        harness_commit: '76fda729799fe9b3848dbe2c211d4b231032b81e',
        test: 'real Harness agent loop; scripted model; controlled local scanner',
        live_model: false,
        fast_path_budget_ms: 500,
        observed_receipt_latency_ms: Math.round(receiptLatency),
        model_request_count: adapter.requests.length,
        tool_calls: calls,
        original_tool_execution_count: sourceCalls,
        checks: {
          pending_receipt: true,
          independent_work_while_pending: true,
          first_poll_pending: true,
          second_poll_approved_with_original: true,
          canary_absent_before_approval_in_model_requests_and_tool_results: true,
          retrieval_tools_do_not_recurse: true,
        },
      }, null, 2) + '\n')
    }
  })

  it('withholds dangerous originals through the agent loop and returns only the redacted view', async () => {
    const canary = `dangerous-${crypto.randomUUID()}`
    const scanner = new ControlledScanner(canary)
    let id = ''
    const adapter = new MockAdapter([
      toolCallResponse('source', 'fetch_document', {}),
      options => {
        id = lastReceipt(options.messages).scan_id
        expect(lastReceipt(options.messages).status).toBe('pending')
        scanner.complete({ status: 'dangerous', redacted: [{ type: 'text', text: 'Useful paragraph. [REDACTED]' }] })
        return toolCallResponse('poll', 'patronus_check_result', { scan_id: id })
      },
      options => {
        expect(lastReceipt(options.messages).status).toBe('dangerous')
        return toolCallResponse('redacted', 'patronus_read_redacted', { scan_id: id })
      },
      options => {
        expect(JSON.stringify(options)).toContain('Useful paragraph. [REDACTED]')
        return textResponse('Used only the redacted paragraph.')
      },
    ])
    const ctx = own(await createHarness(scanner, adapter, { responseWaitMs: 0 }))
    registerTextTool(ctx, 'fetch_document', canary)
    const agent = await createAgent(ctx)
    agent.followup(createUserMessage({ content: [{ type: 'text', text: 'Read the document.' }], source: { kind: 'user' } }))
    await agent.whenIdle()
    expect(adapter.requests).toHaveLength(4)
    expect(JSON.stringify(adapter.requests)).not.toContain(canary)
    expect(JSON.stringify(agent.session.snapshotEvents())).not.toContain(canary)
    expect(JSON.stringify(agent.session.snapshotEvents())).toContain('Used only the redacted paragraph.')
    expect(scanner.submissions).toEqual(['Read the document.', canary])
  })

  it('passes an immediately approved result through without a receipt', async () => {
    const ctx = own(await createHarness({ async scan() { return { status: 'approved' } } }))
    registerTextTool(ctx, 'fast', 'ordinary-result')
    const result = await execute(ctx, 'fast')
    expect(result.isError).toBe(false)
    expect(result.value).toBe('ordinary-result')
  })

  it('removes canonical value, metadata and additional contexts while pending', async () => {
    const canary = `hidden-${crypto.randomUUID()}`
    const metadata = `metadata-${crypto.randomUUID()}`
    const scanner = new ControlledScanner(canary)
    const ctx = own(await createHarness(scanner, undefined, { responseWaitMs: 0 }))
    ctx.tools.register(defineTool({
      name: 'with_metadata', description: 'Fixture with all result channels', parameters: {},
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
        presentationMeta: () => ({ marker: metadata }),
      },
      async execute(_args, exec) {
        exec.deferContext(createUserMessage({ content: [{ type: 'text', text: canary }], source: { kind: 'plugin', plugin: 'fixture' } }))
        return canary
      },
    }))
    const result = await execute(ctx, 'with_metadata')
    expect(lastReceipt(result).status).toBe('pending')
    expect(result.isError).toBe(true)
    expect(result.value).toBeUndefined()
    expect(result.meta).toBeUndefined()
    expect(result.additionalContexts).toBeUndefined()
    expect(JSON.stringify(result)).not.toContain(canary)
    expect(scanner.submissions).toEqual([[canary, canary]])
    expect(JSON.stringify(scanner.submissions)).not.toContain(metadata)
  })

  it('keeps the original result and warns when the backend fails', async () => {
    const canary = 'backend-secret-placeholder'
    const ctx = own(await createHarness({ async scan() { throw new Error(canary) } }))
    registerTextTool(ctx, 'document', canary)
    const result = await execute(ctx, 'document')
    expect(result.isError).toBe(false)
    expect(JSON.stringify(result)).toContain(canary)
    expect(JSON.stringify(result.additionalContexts)).toContain('No security scan was completed')
  })

  it('times out a scan without exposing the original', async () => {
    const canary = 'timed-out-original'
    const ctx = own(await createHarness(new ControlledScanner(canary), undefined, { responseWaitMs: 0, scanTimeoutMs: 20 }))
    registerTextTool(ctx, 'document', canary)
    const receipt = lastReceipt(await execute(ctx, 'document'))
    await delay(40)
    const result = await execute(ctx, 'patronus_check_result', { scan_id: receipt.scan_id })
    expect(lastReceipt(result).status).toBe('failed')
    expect(JSON.stringify(result)).not.toContain(canary)
  })

  it('keeps parallel jobs separate and prevents retrieval by another agent', async () => {
    const scanner = new ControlledScanner('private-result')
    const ctx = own(await createHarness(scanner, undefined, { responseWaitMs: 0 }))
    registerTextTool(ctx, 'first', 'private-result-A')
    registerTextTool(ctx, 'second', 'private-result-B')
    const a = await createAgent(ctx, 'agent-a')
    const b = await createAgent(ctx, 'agent-b')
    const [first, second] = await Promise.all([execute(ctx, 'first', {}, a), execute(ctx, 'second', {}, b)])
    const idA = lastReceipt(first).scan_id
    const idB = lastReceipt(second).scan_id
    expect(idA).not.toBe(idB)
    expect((await execute(ctx, 'patronus_check_result', { scan_id: idA }, b)).value).toMatchObject({ status: 'invalid_reference', code: 'scan_not_available' })
    scanner.complete({ status: 'approved' })
    await delay(0)
    const ownResult = await execute(ctx, 'patronus_check_result', { scan_id: idA }, a)
    expect(JSON.stringify(ownResult)).toContain('private-result-A')
    expect(JSON.stringify(ownResult)).not.toContain('private-result-B')
    expect(lastReceipt(await execute(ctx, 'patronus_check_result', { scan_id: idB }, b)).status).toBe('pending')
  })
})

it.each([0,500])('automatically delivers PII redaction through the Harness agent loop (wait %i)',async responseWaitMs=>{
  const {FakeClient}=await import('./fake-client.ts')
  const canary='PRIVATE-PII-AUTOREDACTION'
  const safe='Version 0.1.0. [REDACTED]'
  const client=new FakeClient({async scan(text){return text===canary?{status:'dangerous',redacted:[{type:'text',text:safe}]}:{status:'approved'}}})
  const check=client.check.bind(client)
  client.check=async params=>{
    const result=await check(params)
    return result.status==='dangerous'?{...result,findings:[{category:'pii'}],coverage:{complete:true,fields_total:1,fields_scanned:1,bytes_total:canary.length,bytes_scanned:canary.length}}:result
  }
  client.readRedacted=async params=>({scan_id:params.scan_id,status:'redacted',result:safe})
  const next=(options:any)=>{
    expect(JSON.stringify(options)).not.toContain(canary)
    const receipt=lastReceipt(options.messages)
    if(receipt.status==='pending')return toolCallResponse('poll','patronus_check_result',{scan_id:receipt.scan_id})
    expect(receipt).toMatchObject({status:'redacted',result:safe})
    return textResponse('Used version 0.1.0 from the redacted document.')
  }
  const adapter=new MockAdapter([toolCallResponse('source','privacy_document',{}),next,next])
  const ctx=own(await createHarness(client,adapter,{responseWaitMs}))
  let calls=0
  registerTextTool(ctx,'privacy_document',canary,()=>{calls++})
  const agent=await createAgent(ctx)
  agent.followup(createUserMessage({content:[{type:'text',text:'Read the document version.'}],source:{kind:'user'}}))
  await agent.whenIdle()
  expect(calls).toBe(1)
  expect(JSON.stringify(adapter.requests)).not.toContain(canary)
  expect(JSON.stringify(agent.session.snapshotEvents())).not.toContain(canary)
  expect(JSON.stringify(adapter.requests)).toContain(safe)
})
