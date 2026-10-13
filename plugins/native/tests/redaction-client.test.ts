import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { LocalClient } from '../../deepseek/src/client.ts'
import { handleHook } from '../src/hooks.ts'
import { handleMcp } from '../src/mcp.ts'

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
      const rpc = async () => { calls++; return {} }
      const result = host === 'claude'
        ? await handleMcp({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'patronus_read_redacted', arguments: { scan_id } } },
          { host, cwd: '/private/tmp', scan: rpc })
        : await handleHook(host, 'PreToolUse', {
          hook_event_name: 'PreToolUse', session_id: 'test-session', cwd: '/private/tmp',
          tool_use_id: 'call-1', tool_name: 'mcp__patronus__patronus_read_redacted', tool_input: {scan_id},
        }, {}, rpc)
      assert.equal(calls, 0)
      assert.match(JSON.stringify(result), /wrong_id_type/)
      assert.doesNotMatch(JSON.stringify(result), /inactive|integration .* enable/)
    }
  })
}

async function disclosureFixture(responses: unknown[]) {
  const root = await mkdtemp(join(tmpdir(), 'patronus-disclosure-client-'))
  const executable = join(root, 'scanner.mjs')
  await writeFile(executable, `#!${process.execPath}
import { createInterface } from 'node:readline';
const responses = ${JSON.stringify(responses)};
let calls = 0;
createInterface({input:process.stdin}).on('line', line => {
  const request = JSON.parse(line);
  process.stdout.write(JSON.stringify({id:request.id,result:responses[Math.min(calls++, responses.length - 1)]})+'\\n');
});
`, { mode: 0o700 })
  const client = new LocalClient({ executable, stateDir: join(root, 'state') })
  return { client, async close() { await client.close(); await rm(root, {recursive:true,force:true}) } }
}

test('disclosure offers carry only fixed types and counts', async () => {
  const scan_id = 'a'.repeat(32)
  const grant_id = 'b'.repeat(32)
  const valid = await disclosureFixture([{ scan_id, status: 'confirmation_required', grant_id, counts: { email: 2 }, expires_in_seconds: 300 }])
  try {
    assert.deepEqual(await valid.client.prepareDisclosure({ session: 's'.repeat(32), scan_id, reveal_pii: ['email'] }),
      { scan_id, status: 'confirmation_required', grant_id, counts: { email: 2 }, expires_in_seconds: 300 })
  } finally { await valid.close() }
  const smuggled = await disclosureFixture([{ scan_id, status: 'confirmation_required', grant_id, counts: { email: 2 }, expires_in_seconds: 300, result: 'ada@example.com' }])
  try {
    await assert.rejects(smuggled.client.prepareDisclosure({ session: 's'.repeat(32), scan_id, reveal_pii: ['email'] }), /invalid response/)
  } finally { await smuggled.close() }
})

test('disclosed reads wait while pending and require the confirmation marker', async () => {
  const scan_id = 'a'.repeat(32)
  const params = { session: 's'.repeat(32), scan_id, grant_id: 'b'.repeat(32) }
  const disclosure = { authorized_pii_types: ['email'], user_confirmed: true, applied: true }
  const f = await disclosureFixture([{ scan_id, status: 'pending' }, { scan_id, status: 'redacted', result: 'ada@example.com', disclosure }])
  try {
    assert.deepEqual(await f.client.readDisclosed(params), { scan_id, status: 'redacted', result: 'ada@example.com', disclosure })
  } finally { await f.close() }
  const unmarked = await disclosureFixture([{ scan_id, status: 'redacted', result: 'ada@example.com' }])
  try {
    await assert.rejects(unmarked.client.readDisclosed(params), /invalid response/)
  } finally { await unmarked.close() }
})
