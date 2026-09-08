import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { LocalClient } from '../../deepseek/src/client.ts'
import { handleHook } from '../src/hooks.ts'

async function fixture(poisonPending = false) {
  const root = await mkdtemp(join(tmpdir(), 'patronus-redaction-client-'))
  const executable = join(root, 'scanner.mjs')
  await writeFile(executable, `#!${process.execPath}
import { createInterface } from 'node:readline';
let calls = 0;
createInterface({input:process.stdin}).on('line', line => {
  const request = JSON.parse(line);
  const result = ++calls < 3
    ? {scan_id:request.params.scan_id,status:'pending',...(${poisonPending} ? {result:'UNVERIFIED'} : {})}
    : {scan_id:request.params.scan_id,status:'redacted',result:'Port 8080. [REDACTED]'};
  process.stdout.write(JSON.stringify({id:request.id,result})+'\\n');
});
`, { mode: 0o700 })
  const client = new LocalClient({ executable, stateDir: join(root, 'state') })
  return { client, async close() { await client.close(); await rm(root, {recursive:true,force:true}) } }
}

test('redacted retrieval waits for refinement instead of exposing pending as unavailable', async () => {
  const f = await fixture()
  try {
    assert.deepEqual(await f.client.readRedacted({session:'s'.repeat(32),scan_id:'a'.repeat(32)}), {
      scan_id:'a'.repeat(32),status:'redacted',result:'Port 8080. [REDACTED]',
    })
  } finally { await f.close() }
})

test('pending refinement cannot smuggle an unverified result through the client', async () => {
  const f = await fixture(true)
  try {
    await assert.rejects(f.client.readRedacted({session:'s'.repeat(32),scan_id:'a'.repeat(32)}), /invalid response/)
  } finally { await f.close() }
})

for (const host of ['codex', 'claude'] as const) {
  test(`${host} rejects static file IDs before any runtime lookup`, async () => {
    for (const scan_id of ['file_' + 'a'.repeat(64), 'a'.repeat(64)]) {
      let calls = 0
      const result = await handleHook(host, 'PreToolUse', {
        hook_event_name: 'PreToolUse', session_id: 'test-session', cwd: '/private/tmp',
        tool_use_id: 'call-1', tool_name: 'mcp__patronus__patronus_read_redacted', tool_input: {scan_id},
      }, {}, async () => { calls++; return {} }, {
        async isQuarantined() { return false }, async quarantine() {}, async arm() {}, async hasPending() { return false },
      })
      assert.equal(calls, 0)
      assert.match(JSON.stringify(result), /wrong_id_type/)
      assert.doesNotMatch(JSON.stringify(result), /inactive|integration .* enable/)
    }
  })
}
