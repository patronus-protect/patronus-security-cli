import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { nativeFixture } from './native-helper.mjs'

test('installed Codex handles a chat pause locally using its native session ID', { timeout: 90000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'patronus-chat-command-'))
  const settings = join(root, 'plugins.json')
  const fixture = await nativeFixture(() => { assert.fail('A local command must not reach the model') }, { PATRONUS_PLUGIN_SETTINGS: settings }, { captureHooks: true })
  try {
    const result = await fixture.exec('chat-pause', { prompt: 'patronus off', expectSuccess: false })
    assert.equal(fixture.server.requests.length, 0)
    // Codex exec --json omits hook reason text; durable state and zero model calls are authoritative.
    assert.match(result.stdout, /"input_tokens":0/)
    const events = (await readFile(fixture.hookCapture, 'utf8')).trim().split('\n').map(JSON.parse)
    const event = events.find(item => item.hook_event_name === 'UserPromptSubmit')
    assert.equal(event.prompt, 'patronus off')
    assert.deepEqual(JSON.parse(await readFile(settings, 'utf8')).disabled_chats.codex, [event.session_id])
  } finally { await fixture.close(); await rm(root, { recursive: true, force: true }) }
})
