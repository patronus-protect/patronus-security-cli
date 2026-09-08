import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'
import { runHost } from './scripted-host.mjs'

test('installed Claude handles a chat pause locally using its native session ID', { timeout: 90000 }, async () => {
  const result = await runHost({ name: 'chat-command-off', tool: 'Bash', input: { command: 'true' }, runtime: true, userPrompt: 'patronus off', timeout: 60000 })
  assert.equal(result.timedOut, false)
  assert.equal(result.messages.length, 0)
  const events = (await readFile(join(result.directory, 'hooks.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse)
  const event = events.find(item => item.hook_event_name === 'UserPromptSubmit')
  assert.equal(event.prompt, 'patronus off')
  assert(JSON.parse(await readFile(join(result.dataDir, 'plugins.json'), 'utf8')).disabled_chats.claude.includes(event.session_id))
  const outputs = await readFile(join(result.directory, 'hook-outputs.jsonl'), 'utf8')
  assert.match(outputs, /Patronus is OFF for this chat/)
})
