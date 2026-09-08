import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { ProtocolEvents, hashProtocolValue, type ProtocolEvent, type ProtocolEventSink } from '../src/protocol-events.ts'
import { createHarness, execute, registerTextTool } from './harness.ts'
import { FakeClient } from './fake-client.ts'
import { fakeCli } from './static-fixture.ts'

class Collector implements ProtocolEventSink {
  readonly events: ProtocolEvent[] = []
  emit(event: ProtocolEvent): void { this.events.push(structuredClone(event)) }
}

describe('DeepSeek protocol events', () => {
  it('sends exactly one sanitized metadata event to the central CLI', async () => {
    const root = await mkdtemp(join(tmpdir(), 'patronus-protocol-test-'))
    const executable = join(root, 'scanner.mjs')
    const captured = join(root, 'event.json')
    await writeFile(executable, `#!${process.execPath}\nimport { writeFileSync } from 'node:fs';\nif (process.argv[3] === 'render') process.exit(0); let body=''; process.stdin.on('data', chunk => body += chunk); process.stdin.on('end', () => writeFileSync(${JSON.stringify(captured)}, JSON.stringify({args:process.argv.slice(2),body})));\n`, { mode: 0o700 })
    try {
      const events = new ProtocolEvents({ executable }, root)
      events.emit({
        kind: 'scan_completed', direction: 'response', tool: 'document',
        session_id: 'private-session', scan_id: 'opaque-scan', status: 'approved', duration_ms: 4.6,
        payload_hash: hashProtocolValue('private-result'),
        arguments: 'must-not-appear', result: 'must-not-appear', error: 'must-not-appear', evidence: 'must-not-appear',
      } as ProtocolEvent & Record<string, string | number>)
      await events.close()
      const call = JSON.parse(await readFile(captured, 'utf8'))
      expect(call.args).toEqual(['protocol', 'append', '--journal-only', '--root', root])
      const event = JSON.parse(call.body)
      expect(Object.keys(event).sort()).toEqual([
        'direction', 'duration_ms', 'event', 'host', 'payload_hash', 'scan_id',
        'schema', 'session_id', 'status', 'timestamp', 'tool_name',
      ])
      expect(event).toMatchObject({ schema: 'patronus.protocol.event.v1', host: 'deepseek', duration_ms: 5 })
      expect(event.session_id).toBe(hashProtocolValue('private-session'))
      expect(call.body).not.toContain('must-not-appear')
      expect(call.body).not.toContain('private-session')
      expect(() => JSON.parse(call.body)).not.toThrow()
    } finally { await rm(root, { recursive: true, force: true }) }
  })

  it('covers response, status and static-scan transitions without changing decisions', async () => {
    const collector = new Collector()
    const client = new FakeClient({ async scan() { return { status: 'approved' } } })
    const fixture = await fakeCli()
    const ctx = await createHarness(client, undefined, {
      executable: fixture.executable, configPath: fixture.configPath, protocolEvents: collector,
    })
    try {
      registerTextTool(ctx, 'work', 'done')
      expect((await execute(ctx, 'work')).value).toBe('done')
      await execute(ctx, 'patronus_check_result', { scan_id: 'unknown' })
      expect((await execute(ctx, 'patronus_scan', { kind: 'file', path: fixture.path })).value).toMatchObject({ status: 'CLEAN', approved: true })
      expect(collector.events.map(event => [event.kind, event.direction, event.status])).toEqual([
        ['scan_started', 'response', 'pending'],
        ['scan_completed', 'response', 'approved'],
        ['scan_completed', 'status', 'unavailable'],
        ['scan_started', 'static', 'pending'],
        ['scan_completed', 'static', 'clean'],
      ])
      expect(collector.events.every(event => /^sha256:[a-f0-9]{64}$/.test(event.payload_hash))).toBe(true)
    } finally {
      await ctx.fiber.dispose()
      await rm(fixture.root, { recursive: true, force: true })
    }
  })

  it('treats CLI logging failures as non-fatal', async () => {
    const events = new ProtocolEvents({ executable: '/missing/patronus-security-scanner' })
    expect(() => events.emit({ kind: 'scan_completed', direction: 'request', tool: 'work', session_id: 'session', status: 'failed', payload_hash: hashProtocolValue('payload') })).not.toThrow()
    await expect(events.close()).resolves.toBeUndefined()
  })

  it.runIf(Boolean(process.env.PATRONUS_SCANNER_BIN))('appends through the real Rust CLI', async () => {
    const root = await mkdtemp(join(tmpdir(), 'patronus-deepseek-protocol-e2e-'))
    await writeFile(join(root, '.git'), 'gitdir: .git-worktree\n')
    try {
      const events = new ProtocolEvents({ executable: process.env.PATRONUS_SCANNER_BIN! }, root)
      events.emit({
        kind: 'scan_completed', direction: 'status', tool: 'patronus_check_result',
        session_id: 'deepseek-e2e-session', scan_id: 'deepseek-e2e-scan', status: 'pending',
        duration_ms: 5, payload_hash: hashProtocolValue({ scan_id: 'deepseek-e2e-scan' }),
      })
      await events.close()
      const protocol = join(root, '.patronus-security-scanner', 'protocol')
      const name = (await readdir(protocol)).find(name => name.endsWith('.jsonl'))
      expect(name).toBeTruthy()
      const stored = (await readFile(join(protocol, name!), 'utf8')).trim().split('\n').map(line => JSON.parse(line))
      expect(stored).toHaveLength(1)
      expect(stored[0]).toMatchObject({
        schema: 'patronus.protocol.record.v1',
        event: { schema: 'patronus.protocol.event.v1', host: 'deepseek', event: 'scan_completed', status: 'pending' },
      })
      expect(await readFile(join(root, '.patronus-security-scanner', 'index.html'), 'utf8')).toContain('deepseek')
    } finally { await rm(root, { recursive: true, force: true }) }
  })
})
