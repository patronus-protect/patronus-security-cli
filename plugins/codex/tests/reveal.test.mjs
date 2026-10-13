import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { readFile, writeFile } from 'node:fs/promises'
import { createInterface } from 'node:readline'
import { join } from 'node:path'
import test from 'node:test'
import { call, done, quote } from './host-helper.mjs'
import { binary, nativeFixture, patronusCall } from './native-helper.mjs'

const email = 'ada.reveal@example.com'
const phone = '202-555-0147'

/** Read a PII result, request an email disclosure, then call the approval tool. */
function revealScript(state, command) {
  return (body, index) => {
    if (index === 1) return [call('exec_command', { cmd: command() })]
    const text = JSON.stringify(body.input ?? [])
    state.seen.push(text)
    state.scan ??= text.match(/[a-f0-9]{32}/)?.[0]
    const grant = text.match(/grant_id\W+([a-f0-9]{32})/)?.[1]
    if (index === 2 && state.scan) return [patronusCall(body, 'patronus_read_redacted', { scan_id: state.scan, reveal_pii: ['email'] }, 'offer')]
    if (index === 3 && grant) return [patronusCall(body, 'patronus_reveal_pii', { scan_id: state.scan, grant_id: grant }, 'reveal')]
    return [done()]
  }
}

async function piiFixture(state, options = {}) {
  let command
  const fixture = await nativeFixture(revealScript(state, () => command), { PATRONUS_RESPONSE_WAIT_MS: '20000' }, { captureHooks: true, ...options })
  await writeFile(join(fixture.root, 'scanner.toml'), '[provider]\nmode = "local"\n[ark]\ncategories = ["prompt_injection", "pii"]\nmax_level = "l1"\ndownload_files = false\n')
  const document = join(fixture.cwd, 'contact.txt')
  await writeFile(document, `Contact: ${email}, phone ${phone}.\n`)
  command = `cat ${quote(document)}`
  return fixture
}

/** An interactive Codex session through app-server; approval requests are answered like the UI. */
async function interactive(fixture, decide) {
  const child = spawn(binary, ['app-server'], { cwd: fixture.cwd, env: fixture.env, stdio: ['pipe', 'pipe', 'pipe'] })
  const pending = new Map()
  const asked = []
  let id = 0, finished
  const completed = new Promise(resolve => { finished = resolve })
  const send = message => child.stdin.write(JSON.stringify(message) + '\n')
  createInterface({ input: child.stdout }).on('line', line => {
    let message
    try { message = JSON.parse(line) } catch { return }
    if (message.id !== undefined && message.method) {
      asked.push({ method: message.method, params: message.params })
      send({ id: message.id, result: decide(message.method, message.params) })
    } else if (message.id !== undefined) {
      const waiter = pending.get(message.id)
      pending.delete(message.id)
      message.error ? waiter?.reject(Error(JSON.stringify(message.error))) : waiter?.resolve(message.result)
    } else if (message.method === 'turn/completed') finished()
  })
  const rpc = (method, params) => new Promise((resolve, reject) => { const key = ++id; pending.set(key, { resolve, reject }); send({ id: key, method, params }) })
  const timer = setTimeout(() => finished(), 120_000)
  try {
    await rpc('initialize', { clientInfo: { name: 'patronus-reveal-test', version: '0.1.0' }, capabilities: { experimentalApi: true } })
    send({ method: 'initialized' })
    const thread = await rpc('thread/start', { cwd: fixture.cwd, approvalPolicy: 'on-request', sandbox: 'workspace-write', ephemeral: true })
    await rpc('turn/start', { threadId: thread.thread.id, input: [{ type: 'text', text: 'Perform the local fixture task.' }] })
    await completed
    return asked
  } finally { clearTimeout(timer); child.stdin.end(); child.kill('SIGTERM') }
}

const answer = allow => (method, params) => {
  if (method === 'mcpServer/elicitation/request') return { action: allow ? 'accept' : 'decline', content: null }
  // Ordinary command approvals for the fixture's own `cat`.
  return { decision: 'accept' }
}

for (const allow of [true, false]) {
  test(`codex interactive: user ${allow ? 'approves' : 'denies'} the disclosure prompt`, { timeout: 200_000 }, async () => {
    const state = { seen: [] }
    const fixture = await piiFixture(state)
    try {
      const asked = await interactive(fixture, answer(allow))
      const hooks = (await readFile(fixture.hookCapture, 'utf8')).trim().split('\n').map(JSON.parse)
      const reveal = asked.filter(item => JSON.stringify(item.params).includes('patronus_reveal_pii'))
      console.log(JSON.stringify({ root: fixture.root, asked: asked.map(item => [item.method, JSON.stringify(item.params).slice(0, 400)]),
        events: hooks.map(h => [h.hook_event_name, h.tool_name, h.permission_mode]) }, null, 1))
      assert.equal(reveal.length, 1, 'Codex must prompt once for the disclosure tool')
      assert(!state.seen.some(text => text.includes(phone)))
      assert.equal(state.seen.some(text => text.includes(email)), allow)
    } finally { await fixture.close() }
  })
}

test('codex exec skips approvals, so the disclosure is denied', { timeout: 180_000 }, async () => {
  const state = { seen: [] }
  const fixture = await piiFixture(state)
  try {
    await fixture.exec('reveal', { expectSuccess: false })
    const hooks = (await readFile(fixture.hookCapture, 'utf8')).trim().split('\n').map(JSON.parse)
    assert(hooks.some(h => h.tool_name?.endsWith('patronus_reveal_pii') && h.permission_mode === 'bypassPermissions'))
    assert.match(state.seen.at(-1), /disclosure_unavailable/)
    assert(!state.seen.some(text => text.includes(email)))
  } finally { await fixture.close() }
})
