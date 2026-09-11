import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as wait } from 'node:timers/promises'
import test from 'node:test'
import { patronusRoot } from '../../deepseek/src/settings.ts'
import { recordProtocolScan } from '../src/protocol.ts'

const config = { host: 'codex' as const, sessionId: 'PRIVATE-SESSION-917', cwd: '/private/tmp' }

test('protocol events contain only sanitized lifecycle metadata', async () => {
  const events: any[] = []
  const result = await recordProtocolScan(config, {
    method: 'response', tool: 'private_tool', callId: 'private-call', payload: 'RAW-RESULT-917',
  }, async () => ({ scan_id: 'abcdef0123456789abcdef0123456789', status: 'pending' }), async (event, root) => { events.push({ event, root }) })

  assert.deepEqual(result, { scan_id: 'abcdef0123456789abcdef0123456789', status: 'pending' })
  assert.equal(events.length, 1)
  assert.deepEqual(events.map(item => item.event.event), ['scan_completed'])
  assert.deepEqual(events.map(item => item.event.status), ['pending'])
  assert.equal(events[0].event.scan_id, 'abcdef0123456789abcdef0123456789')
  assert.match(events[0].event.session_id, /^sha256:[a-f0-9]{64}$/)
  assert.match(events[0].event.payload_hash, /^sha256:[a-f0-9]{64}$/)
  assert.equal(events[0].root, patronusRoot())
  const allowed = ['schema', 'timestamp', 'host', 'session_id', 'event', 'direction', 'tool_name', 'scan_id', 'status', 'duration_ms', 'payload_hash']
  for (const item of events) assert(Object.keys(item.event).every(key => allowed.includes(key)))
  assert(!JSON.stringify(events).includes('PRIVATE-SESSION-917'))
  assert(!JSON.stringify(events).includes('RAW-RESULT-917'))
  assert(!JSON.stringify(events).includes('private-call'))
})

test('protocol append failures do not alter scan results or expose scan errors', async () => {
  const append = async () => { throw Error('PRIVATE-APPEND-ERROR-917') }
  assert.deepEqual(await recordProtocolScan(config, {
    method: 'request', tool: 'Bash', callId: 'call', payload: 'payload',
  }, async () => ({ scan_id: 'abcdef0123456789abcdef0123456789', status: 'approved' }), append), {
    scan_id: 'abcdef0123456789abcdef0123456789', status: 'approved',
  })

  const events: any[] = []
  await assert.rejects(recordProtocolScan(config, {
    method: 'request', tool: 'Bash', callId: 'call', payload: 'payload',
  }, async () => { throw Error('PRIVATE-SCAN-ERROR-917') }, async event => { events.push(event) }), /PRIVATE-SCAN-ERROR-917/)
  assert.equal(events.at(-1).event, 'scan_failed')
  assert.equal(events.at(-1).status, 'failed')
  assert(!JSON.stringify(events).includes('PRIVATE-SCAN-ERROR-917'))
})

test('static MCP protocol identity includes the selected server without persisting it', async () => {
  const events: any[] = []
  const append = async (event: any) => { events.push(event) }
  for (const server of ['first', 'second']) {
    await recordProtocolScan(config, { method: 'static', kind: 'mcp', path: '/private/mcp.json', server }, async () => ({ status: 'CLEAN' }), append)
  }
  assert.notEqual(events[0].payload_hash, events[1].payload_hash)
  assert(!JSON.stringify(events).includes('first'))
  assert(!JSON.stringify(events).includes('second'))
})

test('terminal scan result waits for protocol persistence', async () => {
  let persisted = false
  const result = recordProtocolScan(config, {
    method: 'request', tool: 'Bash', callId: 'call', payload: 'payload',
  }, async () => ({ status: 'approved' }), async () => {
    await wait(30)
    persisted = true
  })
  await wait(5)
  assert.equal(persisted, false)
  assert.deepEqual(await result, { status: 'approved' })
  assert.equal(persisted, true)
})

test('native adapter appends through the real Rust CLI', { skip: !process.env.PATRONUS_SCANNER_BIN }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'patronus-native-protocol-e2e-'))
  await mkdir(join(root, '.git'))
  try {
    const actualConfig = { ...config, cwd: root, executable: process.env.PATRONUS_SCANNER_BIN! }
    await recordProtocolScan(actualConfig, {
      method: 'check', scanId: 'native-e2e-scan',
    }, async () => ({ scan_id: 'native-e2e-scan', status: 'pending' }))
    await recordProtocolScan(actualConfig, { method: 'close' }, async () => ({}))
    const protocol = join(patronusRoot(), 'protocol')
    let jsonl: string | undefined
    let index: string | undefined
    for (let attempt = 0; attempt < 200 && (!jsonl || !index); attempt += 1) {
      jsonl = await readdir(protocol).then(names => names.find(name => name.endsWith('.jsonl'))).catch(() => undefined)
      index = await readFile(join(patronusRoot(), 'index.html'), 'utf8').catch(() => undefined)
      if (!jsonl || !index) await wait(50)
    }
    assert(jsonl)
    assert(index)
    const records = (await readFile(join(protocol, jsonl), 'utf8')).trim().split('\n').map(line => JSON.parse(line))
    assert(records.every(record => record.schema === 'patronus.protocol.record.v1'))
    const events = records.map(record => record.event)
    assert.deepEqual(events.map(event => event.event), ['scan_completed'])
    assert(events.every(event => event.schema === 'patronus.protocol.event.v1'))
    assert.match(index, /native-e2e-scan|codex/)
  } finally { await rm(root, { recursive: true, force: true }) }
})
