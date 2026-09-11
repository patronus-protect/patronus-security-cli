import { access, mkdir, rm, writeFile } from 'node:fs/promises'
import { setTimeout as delay } from 'node:timers/promises'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { expect, it } from 'vitest'
import { MockAdapter, textResponse, toolCallResponse } from 'harness-test-mock'
import { StaticScanner } from '../src/static.ts'
import { createAgent, createHarness, execute, registerTextTool } from './harness.ts'
import { FakeClient } from './fake-client.ts'
import { canary, fakeCli, finding, report } from './static-fixture.ts'

const signal = () => new AbortController().signal

it('withholds a redacted document when its rescan findings were truncated', async () => {
  const fixture = await fakeCli('normal', { status: 'FINDINGS', findings: Array(51).fill(finding) })
  const scanner = new StaticScanner(fixture, signal(), 300_000, true)
  try {
    const scanned: any = await scanner.scan({ kind: 'file', path: fixture.path }, signal())
    expect(scanned.findings_truncated).toBe(true)
    const redacted: any = await scanner.readRedacted(scanned.findings[0].file_id, signal())
    expect(redacted).toMatchObject({ status: 'invalid_reference', code: 'rescan_not_safe' })
    expect(redacted).not.toHaveProperty('result')
  } finally { await rm(fixture.root, { recursive: true, force: true }) }
})

it('returns a rescanned masked document for a static file_id and rejects stale sources', async () => {
  const fixture = await fakeCli('normal', { status: 'FINDINGS', findings: [finding] })
  const scanner = new StaticScanner(fixture, signal(), 300_000, true)
  try {
    const scanned: any = await scanner.scan({ kind: 'file', path: fixture.path }, signal())
    expect(scanned).toMatchObject({ status: 'FINDINGS', redacted_available: true, next_tool: 'patronus_read_redacted' })
    const fileId = scanned.findings[0].file_id
    const redacted: any = await scanner.readRedacted(fileId, signal())
    expect(redacted).toMatchObject({ status: 'redacted', reference_kind: 'static_file', file_id: fileId })
    expect(redacted.result).toBe('[REDACTED]')
    expect(JSON.stringify(redacted)).not.toContain(canary)

    const rescanned: any = await scanner.scan({ kind: 'file', path: fixture.path }, signal())
    await writeFile(fixture.path, `${canary}\nchanged`)
    expect(await scanner.readRedacted(rescanned.findings[0].file_id, signal())).toMatchObject({ status: 'invalid_reference', code: 'source_changed' })
  } finally { await rm(fixture.root, { recursive: true, force: true }) }
})

it('reads a static file_id through the registered redaction tool', async () => {
  const fixture = await fakeCli('normal', { status: 'FINDINGS', findings: [finding] })
  const client = new FakeClient({ async scan() { return { status: 'approved' } } })
  const ctx = await createHarness(client, undefined, { executable: fixture.executable, configPath: fixture.configPath })
  try {
    const scanned: any = (await execute(ctx, 'patronus_scan', { kind: 'file', path: fixture.path })).value
    expect(scanned).toMatchObject({ status: 'FINDINGS', redacted_available: true, next_tool: 'patronus_read_redacted' })
    const fileId = scanned.findings[0].file_id
    const redacted: any = (await execute(ctx, 'patronus_read_redacted', { file_id: fileId })).value
    expect(redacted).toMatchObject({ status: 'redacted', reference_kind: 'static_file', file_id: fileId })
    expect(redacted.result).toBe('[REDACTED]')
    expect(JSON.stringify(redacted)).not.toContain(canary)
  } finally { await ctx.fiber.dispose(); await rm(fixture.root, { recursive: true, force: true }) }
})

it.each(['file_' + 'a'.repeat(64), 'a'.repeat(64)])('rejects static reference %s before runtime retrieval', async scan_id => {
  const client = new FakeClient({ async scan() { return { status: 'approved' } } })
  let lookups = 0
  client.readRedacted = async () => { lookups++; throw Error('must not look up a static file ID') }
  client.check = async () => { lookups++; throw Error('must not look up a static file ID') }
  const ctx = await createHarness(client)
  try {
    for (const tool of ['patronus_read_redacted', 'patronus_check_result']) {
      const result = (await execute(ctx, tool, { scan_id })).value
      expect(result).toMatchObject({ status: 'invalid_reference', code: 'wrong_id_type' })
      expect(JSON.stringify(result)).not.toMatch(/inactive|integration .* enable/)
    }
    expect(lookups).toBe(0)
  } finally { await ctx.fiber.dispose() }
})

it.each(['CLEAN', 'FINDINGS'])('returns only bounded metadata for %s through the native agent loop', async status => {
  const fixture = await fakeCli('normal', { status, findings: status === 'FINDINGS' ? Array(60).fill(finding) : [] })
  const client = new FakeClient({ async scan(text) {
    expect(text).toBe('Scan the requested file.')
    return { status: 'approved' }
  } })
  const adapter = new MockAdapter([
    toolCallResponse('static', 'patronus_scan', { kind: 'file', path: fixture.path }),
    options => {
      expect(JSON.stringify(options)).not.toContain(canary)
      expect(JSON.stringify(options)).toContain(status)
      return textResponse('Scan metadata received.')
    },
  ])
  const ctx = await createHarness(client, adapter, { executable: fixture.executable, configPath: fixture.configPath })
  try {
    const agent = await createAgent(ctx)
    agent.followup(createUserMessage({ content: [{ type: 'text', text: 'Scan the requested file.' }], source: { kind: 'user' } }))
    await agent.whenIdle()
    expect(adapter.requests).toHaveLength(2)
    expect(JSON.stringify(adapter.requests)).not.toContain(canary)
    expect(JSON.stringify(agent.session.snapshotEvents())).not.toContain(canary)
    expect(client.submissions.map(item => item.payload)).toEqual(['Scan the requested file.'])
    const result = (await execute(ctx, 'patronus_scan', { kind: 'file', path: fixture.path })).value as any
    expect(result).toMatchObject({ status, approved: status === 'CLEAN', coverage: { complete: true } })
    expect(Buffer.byteLength(JSON.stringify(result))).toBeLessThan(16_384)
    expect(result.findings).toHaveLength(status === 'FINDINGS' ? 50 : 0)
    expect(result.findings_truncated).toBe(status === 'FINDINGS')
    if (status === 'FINDINGS') {
      expect(Object.keys(result.findings[0]).sort()).toEqual(['category', 'confidence', 'file_id', 'level', 'line_end', 'line_start'])
      expect(result.findings[0].file_id).toMatch(/^file_[a-f0-9]{64}$/)
    }
    expect(result).toMatchObject({ reference_kind: 'static_file', runtime_result_available: false })
    expect((await ctx.skills.list()).some(skill => skill.name === 'patronus-static-scan')).toBe(true)
    for (const call of (await fixture.calls()).filter(call => call.args[0] === 'scan')) await expect(access(call.cwd)).rejects.toThrow()
  } finally { await ctx.fiber.dispose(); await rm(fixture.root, { recursive: true, force: true }) }
})

it.each(['repo', 'directory', 'file'])('passes %s paths literally, freezes config and removes private outputs', async kind => {
  const fixture = await fakeCli()
  const scanner = new StaticScanner(fixture, signal())
  try {
    const path = kind === 'file' ? fixture.path : fixture.targetDir
    expect(await scanner.scan({ kind, path }, signal())).toMatchObject({ status: 'CLEAN' })
    const calls = await fixture.calls()
    expect(calls).toHaveLength(2)
    expect(calls[0].args).toEqual(['config', 'print', '--format', 'json', '--config', fixture.configPath])
    expect(calls[1].args.slice(0, 2)).toEqual(['scan', kind])
    expect(calls[1].args.slice(-2)).toEqual(['--', path])
    expect(calls[1].snapshot).toContain('"download_files" = false')
    expect(calls[1].snapshot).toContain('"include_chunk_content" = false')
    expect(calls[1].snapshot).toContain('"include_evidence_text" = false')
    expect(calls[1].snapshot).toContain('"mode" = "local"')
    expect(calls[1].snapshot).toContain('"categories" = ["prompt_injection"]')
    expect(calls[1].snapshot).toContain('"include_hidden" = true')
    expect(calls[1].snapshot).toContain('"respect_gitignore" = false')
    expect(calls[1].snapshot).toContain('"max_file_bytes" = 123456')
    expect(calls[1].snapshot).toContain('custom-ignore/**')
    expect(calls[0].cwd).toBe(process.cwd())
    expect(calls[1].mode).toBe(0o700)
    await expect(access(calls[1].cwd)).rejects.toThrow()
  } finally { await rm(fixture.root, { recursive: true, force: true }) }
})

it.each(['webmcp', 'missing-provider', 'config-noise', 'config-error', 'error', 'noise', 'huge'])('fails closed on %s without echoing process output', async mode => {
  const fixture = await fakeCli(mode)
  const scanner = new StaticScanner(fixture, signal())
  try {
    const result = await scanner.scan({ kind: 'file', path: fixture.path }, signal())
    expect(result).toMatchObject({ status: 'FAILED', approved: false })
    expect(JSON.stringify(result)).not.toContain(canary)
    const calls = await fixture.calls()
    if (['webmcp', 'missing-provider', 'config-noise', 'config-error'].includes(mode)) expect(calls).toHaveLength(1)
    for (const call of calls.filter(call => call.args[0] === 'scan')) await expect(access(call.cwd)).rejects.toThrow()
  } finally { await rm(fixture.root, { recursive: true, force: true }) }
})

it.each([
  { status: 'INCOMPLETE', coverage: { ...report.coverage, skipped_files: 1 } },
  { coverage: { ...report.coverage, analyzed_files: 0 } },
  { coverage: { ...report.coverage, analyzed_bytes: 1 } },
  { coverage: { ...report.coverage, eligible_files: 0, analyzed_files: 0 } },
  { coverage: { ...report.coverage, failures: 1 } },
  { coverage: { ...report.coverage, degraded: true } },
  { status: canary }, { schema: canary }, { coverage: { complete: true } },
  { status: 'FINDINGS', findings: [{ ...finding, category: canary }] },
])('does not approve incomplete or malformed reports (%j)', async override => {
  const fixture = await fakeCli('normal', override)
  try {
    const result = await new StaticScanner(fixture, signal()).scan({ kind: 'file', path: fixture.path }, signal())
    expect(result).toMatchObject({ approved: false })
    expect(JSON.stringify(result)).not.toContain(canary)
    expect(Buffer.byteLength(JSON.stringify(result))).toBeLessThan(16_384)
  } finally { await rm(fixture.root, { recursive: true, force: true }) }
})

it.each([
  ['status', { status: ['CLEAN'] }],
  ['ark_max_level', { ark_max_level: ['l1'] }],
  ['category', { status: 'FINDINGS', findings: [{ ...finding, category: ['prompt_injection'] }] }],
  ['level', { status: 'FINDINGS', findings: Array(50).fill({ ...finding, level: [[['l1']]] }) }],
] as const)('rejects a malformed %s enum rather than projecting its original value', async (_field, override) => {
  const fixture = await fakeCli('normal', override)
  try {
    const result = await new StaticScanner(fixture, signal()).scan({ kind: 'file', path: fixture.path }, signal())
    expect(result).toEqual({ schema: 'patronus.deepseek.static.v1', status: 'FAILED', approved: false, reason: 'scan_unavailable' })
    expect(JSON.stringify(result)).not.toContain(canary)
  } finally { await rm(fixture.root, { recursive: true, force: true }) }
})

it('rejects an array-valued kind before starting a CLI process', async () => {
  const fixture = await fakeCli()
  try {
    expect(await new StaticScanner(fixture, signal()).scan({ kind: ['file'], path: fixture.path }, signal())).toMatchObject({ status: 'FAILED', approved: false })
    expect(await fixture.calls()).toEqual([])
  } finally { await rm(fixture.root, { recursive: true, force: true }) }
})

it.each(['noise', 'error'])('keeps %s CLI output out of every native model request and session event', async mode => {
  const fixture = await fakeCli(mode)
  const client = new FakeClient({ async scan(text) {
    expect(text).toBe('Scan the requested file.')
    return { status: 'approved' }
  } })
  const adapter = new MockAdapter([
    toolCallResponse('static-failure', 'patronus_scan', { kind: 'file', path: fixture.path }),
    options => {
      expect(JSON.stringify(options)).toContain('FAILED')
      expect(JSON.stringify(options)).toContain('Patronus protection is inactive')
      expect(JSON.stringify(options)).not.toContain(canary)
      return textResponse('No read approval is available.')
    },
  ])
  const ctx = await createHarness(client, adapter, { executable: fixture.executable, configPath: fixture.configPath })
  try {
    const agent = await createAgent(ctx)
    agent.followup(createUserMessage({ content: [{ type: 'text', text: 'Scan the requested file.' }], source: { kind: 'user' } }))
    await agent.whenIdle()
    expect(adapter.requests).toHaveLength(2)
    for (const request of adapter.requests) expect(JSON.stringify(request)).not.toContain(canary)
    expect(JSON.stringify(agent.session.snapshotEvents())).not.toContain(canary)
    expect(client.submissions.map(item => item.payload)).toEqual(['Scan the requested file.'])
  } finally { await ctx.fiber.dispose(); await rm(fixture.root, { recursive: true, force: true }) }
})

it.each(['timeout', 'abort', 'dispose'])('bounds %s, kills the child and cleans its private directory', async mode => {
  const fixture = await fakeCli('hang')
  const parent = new AbortController()
  const caller = new AbortController()
  const scanner = new StaticScanner(fixture, parent.signal, mode === 'timeout' ? 2000 : 10_000)
  try {
    const started = Date.now()
    const pending = scanner.scan({ kind: 'file', path: fixture.path }, caller.signal)
    expect(await scanner.scan({ kind: 'file', path: fixture.path }, signal())).toMatchObject({ reason: 'busy' })
    while ((await fixture.calls()).length < 2 && Date.now() - started < 3000) await delay(10)
    expect(await fixture.calls()).toHaveLength(2)
    if (mode === 'abort') caller.abort()
    if (mode === 'dispose') parent.abort()
    expect(await pending).toMatchObject({ status: 'FAILED', reason: mode === 'timeout' ? 'timeout' : 'aborted' })
    await scanner.close()
    expect(Date.now() - started).toBeLessThan(5000)
    for (const call of await fixture.calls()) {
      if (call.args[0] === 'scan') await expect(access(call.cwd)).rejects.toThrow()
      expect(() => process.kill(call.pid, 0)).toThrow()
    }
  } finally { parent.abort(); await scanner.close(); await rm(fixture.root, { recursive: true, force: true }) }
})

it('does not treat an agent-scoped tool shadowing the registered static tool name as Patronus-owned', async () => {
  const client = new FakeClient({ async scan() { return { status: 'approved' } } })
  const ctx = await createHarness(client)
  let calls = 0
  try {
    const agent = await createAgent(ctx)
    registerTextTool(agent.ctx, 'patronus_scan', canary, () => { calls++ })
    const result = await execute(ctx, 'patronus_scan', {}, agent)
    expect(calls).toBe(1)
    expect(result.isError).toBe(false)
    expect(client.submissions).toHaveLength(1)
    expect(client.submissions[0]).toMatchObject({ direction: 'response', payload: canary })
  } finally { await ctx.fiber.dispose() }
})

it('never executes a CLI supplied by the target repository, even from a nested target', async () => {
  const fixture = await fakeCli()
  await mkdir(`${fixture.root}/.git`)
  try {
    expect(await new StaticScanner(fixture, signal()).scan({ kind: 'file', path: fixture.path }, signal())).toMatchObject({ status: 'FAILED', approved: false })
    expect(await fixture.calls()).toEqual([])
  } finally { await rm(fixture.root, { recursive: true, force: true }) }
})

it.each(['api', 'hybrid'])('preserves explicit %s provider routing without local fallback', async provider => {
  const fixture = await fakeCli(provider)
  try {
    const result = await new StaticScanner(fixture, signal()).scan({ kind: 'file', path: fixture.path }, signal())
    expect(result).toMatchObject({ status: 'CLEAN', approved: true, provider: provider === 'api' ? 'api' : 'local' })
    const calls = await fixture.calls()
    expect(calls).toHaveLength(2)
    expect(calls[1].snapshot).toContain(provider)
  } finally { await rm(fixture.root, { recursive: true, force: true }) }
})

it.each(['url','mcp'])('returns explicit %s scan metadata through the registered host tool', async kind => {
  const fixture = await fakeCli('normal', {schema:'patronus.remote.scan.v1',kind,provider:'api',status:'CLEAN',approved:true,complete:true,categories:['injection','pii','dlp','threat'],findings:[],jobs:1,duration_ms:10})
  const client = new FakeClient({async scan() { return {status:'approved'} }})
  const ctx = await createHarness(client, undefined, {executable:fixture.executable,configPath:fixture.configPath})
  try {
    const path=kind==='url'?'https://example.org/page':'./servers.json'
    const result=(await execute(ctx,'patronus_scan',kind==='mcp'?{kind,path,server:'selected'}:{kind,path})).value
    expect(result).toMatchObject({kind,approved:true,complete:true,provider:'api'})
    expect(JSON.stringify(result)).not.toContain(canary)
    expect((await fixture.calls())[0].args.slice(-2)).toEqual(['--',path])
  }finally{await ctx.fiber.dispose();await rm(fixture.root,{recursive:true,force:true})}
})
