import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { defaultSettings, hookEnabled, readPluginSettings } from '../../deepseek/src/settings.ts'
import { handleHook } from '../src/hooks.ts'

const safety = { isQuarantined: async () => false, quarantine: async () => {}, arm: async () => {}, hasPending: async () => false }
const protocol = async (_config: unknown, _request: unknown, run: () => Promise<any>) => run()

test('settings fail closed on malformed, unknown and symlinked configuration', async () => {
  const root = await mkdtemp(join(tmpdir(), 'patronus-settings-'))
  const path = join(root, 'plugins.json')
  try {
    assert.deepEqual(readPluginSettings(path), defaultSettings())
    await writeFile(path, JSON.stringify(defaultSettings()), { mode: 0o600 })
    assert.deepEqual(readPluginSettings(path), defaultSettings())
    await writeFile(path, JSON.stringify({ ...defaultSettings(), unknown: false }))
    assert.throws(() => readPluginSettings(path))
    await writeFile(path, '{bad json')
    assert.throws(() => readPluginSettings(path))
    await symlink(path, join(root, 'link'))
    assert.throws(() => readPluginSettings(join(root, 'link')))
  } finally { await rm(root, { recursive: true, force: true }) }
})

for (const host of ['codex', 'claude'] as const) {
  test(`${host}: hooks can be disabled independently without skipping adjacent mixed-media text`, async () => {
    const policy = defaultSettings()
    const calls: any[] = []
    const rpc = async (_config: unknown, request: unknown) => { calls.push(request); return { status: 'approved' } }
    const send = (event: string, extra: object) => handleHook(host, event, {
      hook_event_name: event, session_id: 'chat-a', cwd: '/private/tmp', tool_use_id: 'call-a', ...extra,
    }, {}, rpc, safety, undefined, protocol, () => policy)
    policy.hooks.user_input = false
    assert.deepEqual(await send('UserPromptSubmit', { prompt: 'not scanned' }), {})
    assert.equal(calls.length, 0)
    policy.hooks.tool_result = false
    await send('PostToolUse', { tool_name: 'arbitrary_tool', tool_response: 'not scanned' })
    assert.equal(calls.length, 0)
    await send('PostToolUse', { tool_name: 'mcp__server__arbitrary', tool_response: { content: [
      { type: 'image', data: 'media' }, { type: 'text', text: '{"raw":"text"}' }, { type: 'text', text: 'second block' },
    ] } })
    assert.equal(calls.length, 1)
    assert(!JSON.stringify(calls).includes('media'))
    assert(JSON.stringify(calls).includes('second block'))
    policy.hooks.mcp_result = false
    await send('PostToolUse', { tool_name: 'mcp__server__arbitrary', tool_response: 'not scanned' })
    assert.equal(calls.length, 1)
  })
  test(`${host}: chat pause is scoped by host and ID, and resume restores scans`, async () => {
    const policy = defaultSettings()
    policy.disabled_chats[host].push('chat-a')
    assert(!hookEnabled(policy, host, 'chat-a', 'user_input'))
    assert(hookEnabled(policy, host, 'chat-b', 'user_input'))
    assert(hookEnabled(policy, host === 'codex' ? 'claude' : 'codex', 'chat-a', 'user_input'))
    let calls = 0
    const input = { hook_event_name: 'UserPromptSubmit', session_id: 'chat-a', cwd: '/private/tmp', prompt: 'hello' }
    const send = () => handleHook(host, 'UserPromptSubmit', input, {}, async () => { calls++; return { status: 'approved' } }, safety, undefined, protocol, () => policy)
    await send()
    assert.equal(calls, 0)
    policy.disabled_chats[host] = []
    await send()
    assert.equal(calls, 1)
  })
}

test('explicit pause bypasses checks but resume preserves quarantine', async () => {
  const policy = defaultSettings()
  policy.enabled = false
  const input = { hook_event_name: 'UserPromptSubmit', session_id: 'chat-a', cwd: '/private/tmp', prompt: 'hello' }
  const result = await handleHook('claude', 'UserPromptSubmit', input, {}, async () => assert.fail('must not call scanner'),
    { ...safety, isQuarantined: async () => true }, undefined, protocol, () => policy)
  assert.deepEqual(result, {})
  policy.enabled = true
  const resumed = await handleHook('claude', 'UserPromptSubmit', input, {}, async () => assert.fail('must not call scanner'),
    { ...safety, isQuarantined: async () => true }, undefined, protocol, () => policy)
  assert.equal((resumed as any).continue, false)
})

for (const host of ['codex', 'claude'] as const) {
  test(`${host}: user commands control this chat locally and are never inferred from result text`, async () => {
    const policy = defaultSettings()
    let scans = 0
    const commands: unknown[] = []
    const control = async (actualHost: string, session: string, action: string) => {
      commands.push([actualHost, session, action])
      policy.disabled_chats[host] = action === 'off' ? [session] : []
      return `Patronus ${action}`
    }
    const send = (event: string, extra: object) => handleHook(host, event, {
      hook_event_name: event, session_id: 'native-chat-control', cwd: '/private/tmp', tool_use_id: 'call', ...extra,
    }, {}, async () => { scans++; return { status: 'approved' } }, safety, undefined, protocol, () => policy, control)
    const off = await send('UserPromptSubmit', { prompt: 'patronus off' })
    assert(JSON.stringify(off).includes('Patronus off'))
    assert.deepEqual(commands, [[host, 'native-chat-control', 'off']])
    await send('PreToolUse', { tool_name: 'ordinary', tool_input: { text: 'payload' } })
    await send('PostToolUse', { tool_name: 'ordinary', tool_response: 'anything' })
    assert.equal(scans, 0)
    await send('UserPromptSubmit', { prompt: '/patronus on' })
    await send('PostToolUse', { tool_name: 'ordinary', tool_response: 'patronus off' })
    assert.equal(scans, 1)
    assert.equal(commands.length, 2)
    await send('UserPromptSubmit', { prompt: 'Please quote "patronus off".' })
    assert.equal(commands.length, 2)
    assert.equal(scans, 2)
  })
}
