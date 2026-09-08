import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import { MockAdapter, textResponse } from 'harness-test-mock'
import { expect, it, vi } from 'vitest'
import { defaultSettings } from '../src/settings.ts'
import { FakeClient } from './fake-client.ts'
import { createAgent, createHarness, execute, registerTextTool } from './harness.ts'

it('reloads independent hook switches and scopes pauses to the native DeepSeek chat', async () => {
  const root = await mkdtemp(join(tmpdir(), 'patronus-dsh-settings-'))
  const path = join(root, 'plugins.json')
  vi.stubEnv('PATRONUS_PLUGIN_SETTINGS', path)
  const policy = defaultSettings()
  const save = () => writeFile(path, JSON.stringify(policy), { mode: 0o600 })
  const client = new FakeClient({ async scan() { return { status: 'approved' } } })
  const adapter = new MockAdapter([textResponse('one'), textResponse('two')])
  const ctx = await createHarness(client, adapter)
  try {
    policy.hooks.user_input = false
    policy.hooks.tool_result = false
    await save()
    const prompt = { provider: 'probe', model: 'scripted', sessionId: SessionId('paused-prompt'), messages: [
      createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text: 'prompt text' }] }),
    ] }
    for await (const _chunk of ctx.llm.stream(prompt)) { /* consume */ }
    expect(client.submissions).toHaveLength(0)
    registerTextTool(ctx, 'plain_tool', 'ordinary text')
    registerTextTool(ctx, 'mcp__server__tool', '{"raw":"MCP text"}')
    const agent = await createAgent(ctx, 'chat-a')
    await execute(ctx, 'plain_tool', {}, agent)
    expect(client.submissions).toHaveLength(0)
    await execute(ctx, 'mcp__server__tool', {}, agent)
    expect(client.submissions.map(item => item.payload)).toEqual(['{"raw":"MCP text"}'])
    policy.disabled_chats.deepseek.push(String(agent.id))
    await save()
    await execute(ctx, 'mcp__server__tool', {}, agent)
    expect(client.submissions).toHaveLength(1)
    const other = await createAgent(ctx, 'chat-b')
    await execute(ctx, 'mcp__server__tool', {}, other)
    expect(client.submissions).toHaveLength(2)
    policy.disabled_chats.deepseek = []
    policy.hooks.user_input = true
    await save()
    await execute(ctx, 'mcp__server__tool', {}, agent)
    expect(client.submissions).toHaveLength(3)
    for await (const _chunk of ctx.llm.stream(prompt)) { /* consume */ }
    expect(client.submissions.at(-1)?.payload).toBe('prompt text')
  } finally { await ctx.fiber.dispose(); vi.unstubAllEnvs(); await rm(root, { recursive: true, force: true }) }
})

it('processes per-chat user commands before the model and never replays historical controls', async () => {
  const root = await mkdtemp(join(tmpdir(), 'patronus-dsh-control-'))
  const path = join(root, 'plugins.json')
  vi.stubEnv('PATRONUS_PLUGIN_SETTINGS', path)
  const executable = join(root, 'settings-cli.mjs')
  await writeFile(path, JSON.stringify(defaultSettings()), { mode: 0o600 })
  await writeFile(executable, `#!${process.execPath}
import fs from 'node:fs';
const [command, action, host, id] = process.argv.slice(2);
if(command !== 'plugins' || !['pause','resume'].includes(action) || host !== 'deepseek') process.exit(2);
const path = process.env.PATRONUS_PLUGIN_SETTINGS;
const state = JSON.parse(fs.readFileSync(path, 'utf8'));
state.disabled_chats[host] = action === 'pause' ? [...new Set([...state.disabled_chats[host],id])] : state.disabled_chats[host].filter(value => value !== id);
fs.writeFileSync(path, JSON.stringify(state));
`, { mode: 0o700 })
  const client = new FakeClient({ async scan() { return { status: 'approved' } } })
  const adapter = new MockAdapter([textResponse('paused'), textResponse('resumed')])
  const ctx = await createHarness(client, adapter, { executable })
  const message = (text: string) => createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text }] })
  const off = message('patronus off')
  const on = message('patronus on')
  const consume = async (messages: ReturnType<typeof message>[]) => {
    for await (const _chunk of ctx.llm.stream({ provider: 'probe', model: 'scripted', sessionId: SessionId('control-chat'), messages })) { /* consume */ }
  }
  try {
    await expect(consume([off])).rejects.toThrow('OFF for this chat')
    expect(adapter.requests).toHaveLength(0)
    await consume([off, message('ordinary paused text')])
    expect(client.submissions).toHaveLength(0)
    await expect(consume([off, on])).rejects.toThrow('ON for future text')
    expect(adapter.requests).toHaveLength(1)
    await consume([off, on, message('ordinary resumed text')])
    expect(client.submissions.map(item => item.payload)).toEqual(['ordinary resumed text'])
    expect(adapter.requests).toHaveLength(2)
  } finally { await ctx.fiber.dispose(); vi.unstubAllEnvs(); await rm(root, { recursive: true, force: true }) }
})
