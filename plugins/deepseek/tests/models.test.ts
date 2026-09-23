import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import { expect, it } from 'vitest'
import { LocalClient } from '../src/client.ts'
import { createHarness, execute, lastReceipt, registerTextTool } from './harness.ts'

/** Opt-in: real prepared model assets, no LLM calls or verdict substitution. */
it('gates requests and pending responses with the selected local model profile', async () => {
  const executable = process.env.PATRONUS_TEST_SCANNER
  const configPath = process.env.PATRONUS_TEST_CONFIG
  const fixturePath = process.env.PATRONUS_MODEL_FIXTURE
  const level = process.env.PATRONUS_MODEL_LEVEL
  if (!executable || !configPath || !fixturePath || !['l2', 'l3'].includes(level ?? '')) {
    throw new Error('Set PATRONUS_TEST_SCANNER, PATRONUS_TEST_CONFIG, PATRONUS_MODEL_FIXTURE and PATRONUS_MODEL_LEVEL.')
  }
  const original = await readFile(fixturePath, 'utf8')
  // A plain substring stays visible even when a leaked multiline fixture is JSON-escaped.
  const marker = original.match(/[A-Za-z ]{40,}/)?.[0]
  if (!marker) throw new Error('The model fixture must contain a distinctive plain-text passage.')
  const category = level === 'l2' ? 'prompt_injection' : 'threat'
  const root = await mkdtemp(join(tmpdir(), `patronus-${level}-integration-`))
  const client = new LocalClient({ executable, configPath, stateDir: join(root, 'scanner') })
  const ctx = await createHarness(client, undefined, { responseWaitMs: 0 })
  let actionCalls = 0
  let documentCalls = 0
  const states: string[] = []
  try {
    const hello = await client.hello()
    expect(hello.ark_version).toBe('0.1.8')
    ctx.tools.register(defineTool({
      name: 'process_document', description: 'Process the supplied document.',
      parameters: { text: { type: 'string', required: true } },
      output: { schema: { type: 'string' }, render: (_args, text) => [{ type: 'text', text }] },
      async execute() { actionCalls++; return 'Completed.' },
    }))
    let promptStatus: string | undefined
    try {
      for await (const _ of ctx.llm.stream({
        provider: 'probe', model: 'scripted', sessionId: SessionId(crypto.randomUUID()),
        messages: [createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: original }] })],
      })) { /* The prompt must be withheld before the adapter runs. */ }
    } catch (error) { promptStatus = JSON.parse((error as Error).message).status }
    expect(promptStatus).toBe('dangerous')
    await execute(ctx, 'process_document', { text: original })
    expect(actionCalls).toBe(1)

    registerTextTool(ctx, 'fetch_document', original, () => { documentCalls++ })
    const withheld = await execute(ctx, 'fetch_document')
    expect(JSON.stringify(withheld)).not.toContain(marker)
    const pending = lastReceipt(withheld)
    expect(pending.status).toBe('pending')
    states.push(pending.status)
    let answer = await execute(ctx, 'patronus_check_result', { scan_id: pending.scan_id })
    expect(JSON.stringify(answer)).not.toContain(marker)
    let checked = lastReceipt(answer)
    const deadline = Date.now() + hello.runtime.scan_timeout_ms + 1000
    while (checked.status === 'pending' && Date.now() < deadline) {
      await delay(100)
      answer = await execute(ctx, 'patronus_check_result', { scan_id: pending.scan_id })
      expect(JSON.stringify(answer)).not.toContain(marker)
      checked = lastReceipt(answer)
    }
    expect(checked.status).toBe('dangerous')
    const result = checked as typeof checked & { findings: { category: string; level?: string }[]; coverage: { complete: boolean }; result?: unknown }
    expect(result.coverage.complete).toBe(true)
    expect(result.findings.some(finding => finding.category === category && finding.level === level)).toBe(true)
    expect(result).not.toHaveProperty('result')
    states.push(result.status)
    const redacted = lastReceipt(await execute(ctx, 'patronus_read_redacted', { scan_id: pending.scan_id }))
    expect(redacted.status).toBe('redacted')
    const text = (redacted as typeof redacted & { result: string }).result
    expect(typeof text).toBe('string')
    expect(text).not.toContain(original)
    expect(text).toContain('[REDACTED]')
    states.push(redacted.status)
    expect(documentCalls).toBe(1)
    const evidence = {
      ark_version: hello.ark_version, level, category, scanner: 'real local Ark model; no verdict simulation',
      recorded_at: new Date().toISOString(), response_wait_ms: 0,
      request: 'dangerous', action_calls: actionCalls, document_calls: documentCalls,
      states, complete_coverage: result.coverage.complete, dangerous_original_retrievable: false, passed: true,
      observed_finding_levels: [...new Set(result.findings.map(finding => finding.level))],
    }
    if (process.env.PATRONUS_PROBE_REPORT) await writeFile(process.env.PATRONUS_PROBE_REPORT, JSON.stringify(evidence, null, 2) + '\n')
    console.log(JSON.stringify(evidence))
  } finally {
    await ctx.fiber.dispose()
    await rm(root, { recursive: true, force: true })
  }
})
