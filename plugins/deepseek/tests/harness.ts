import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import AgentRegistry from '@deepseek-ai/dsh-agent'
import AgentLoop from '@deepseek-ai/dsh-agent-loop'
import LlmRuntime, { ToolCallId } from '@deepseek-ai/dsh-llm'
import SessionStore, { SessionId } from '@deepseek-ai/dsh-session'
import SessionProjection from '@deepseek-ai/dsh-session-projection'
import SkillRegistry from '@deepseek-ai/dsh-skill'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime, { defineTool } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import { MockAdapter, textResponse } from 'harness-test-mock'
import * as patronus from '../src/index.ts'
import { FakeClient, type TestScanner, type TestVerdict } from './fake-client.ts'

export class ControlledScanner implements TestScanner {
  submissions: JsonValue[] = []
  pending: Array<(verdict: TestVerdict) => void> = []

  constructor(private readonly withheld: string) {}

  async scan(text: JsonValue): Promise<TestVerdict> {
    this.submissions.push(structuredClone(text))
    if (!JSON.stringify(text).includes(this.withheld)) return { status: 'approved' }
    return new Promise(resolve => { this.pending.push(resolve) })
  }

  complete(verdict: TestVerdict): void {
    const resolve = this.pending.shift()
    if (!resolve) throw new Error('No pending scan')
    resolve(verdict)
  }
}

export async function createHarness(
  scanner: TestScanner | patronus.RuntimeClient | undefined,
  adapter = new MockAdapter([textResponse('done')]),
  options: Omit<patronus.Config, 'client'> & { scanTimeoutMs?: number } = {},
): Promise<Context> {
  const stateDir = options.stateDir ?? await mkdtemp(join(tmpdir(), 'patronus-harness-state-'))
  const ctx = new Context()
  if (options.stateDir === undefined) ctx.effect(() => () => rm(stateDir, { recursive: true, force: true }))
  await ctx.plugin(LlmRuntime)
  await ctx.plugin(SessionStore)
  await ctx.plugin(SessionProjection)
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  await ctx.plugin(AgentRegistry)
  await ctx.plugin(AgentLoop, { agents: [] })
  await ctx.plugin(SkillRegistry)
  const { scanTimeoutMs, ...pluginOptions } = options
  const client = scanner === undefined ? undefined : 'hello' in scanner ? scanner : new FakeClient(scanner, scanTimeoutMs)
  // ProtocolEvents has separate CLI integration tests; ordinary mocks own no journal processes.
  await ctx.plugin(patronus, { client, protocolEvents: { emit() {} }, ...pluginOptions, stateDir })
  ctx.llm.registerAdapter(['probe'], adapter)
  return ctx
}

export const createAgent = (ctx: Context, name = 'probe') =>
  ctx.agentLoop.create(SessionId(name), { provider: 'probe', model: 'scripted' })

const defaultAgents = new WeakMap<Context, ReturnType<typeof createAgent>>()
function defaultAgent(ctx: Context): ReturnType<typeof createAgent> {
  let agent = defaultAgents.get(ctx)
  if (!agent) { agent = createAgent(ctx, `direct-${crypto.randomUUID()}`); defaultAgents.set(ctx, agent) }
  return agent
}

export const execute = async (ctx: Context, name: string, args: object = {}, agent?: Awaited<ReturnType<typeof createAgent>>) =>
  ctx.tools.execute({
    callId: ToolCallId(crypto.randomUUID()), name, arguments: args,
    signal: new AbortController().signal,
    agent: agent ?? await defaultAgent(ctx),
  })

export function registerTextTool(ctx: Context, name: string, value: string, onCall = () => {}): void {
  ctx.tools.register(defineTool({
    name, description: name, parameters: {},
    output: { schema: { type: 'string' }, render: (_args, text) => [{ type: 'text', text }] },
    async execute() { onCall(); return value },
  }))
}

/** Find only JSON emitted as tool text; no scan ID is preprogrammed into the replay. */
export function lastReceipt(value: unknown): { status: string; scan_id: string } {
  const candidates: Array<{ status: string; scan_id: string }> = []
  const visit = (item: unknown): void => {
    if (!item || typeof item !== 'object') return
    const record = item as Record<string, unknown>
    if (record.type === 'text' && typeof record.text === 'string') {
      try {
        const parsed = JSON.parse(record.text)
        if (typeof parsed.status === 'string' && typeof parsed.scan_id === 'string') candidates.push(parsed)
      } catch { /* Ordinary tool text is not a receipt. */ }
    }
    for (const nested of Object.values(record)) visit(nested)
  }
  visit(value)
  const receipt = candidates.at(-1)
  if (!receipt) throw new Error('No receipt in model input')
  return receipt
}
