import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { createUserMessage, ToolCallId } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import { MockAdapter, textResponse, toolCallResponse } from 'harness-test-mock'
import { expect, it } from 'vitest'
import { ControlledScanner, createAgent, createHarness, execute, lastReceipt, registerTextTool } from './harness.ts'

const user = (text: string) => createUserMessage({ content: [{ type: 'text' as const, text }], source: { kind: 'user' as const } })

it('keeps a finalizer-modified session usable and warns the model', async () => {
  const stateDir = await mkdtemp(join(tmpdir(), 'patronus-degraded-'))
  const id = SessionId(crypto.randomUUID())
  const canary = 'FINALIZER-UNSCANNED-ORIGINAL'
  const adapter = new MockAdapter([toolCallResponse('source', 'document', {}), textResponse('continued')])
  const ctx = await createHarness({ async scan(text) {
    return JSON.stringify(text).includes(canary)
      ? { status: 'dangerous', redacted: [{ type: 'text', text: '[REDACTED]' }] }
      : { status: 'approved' }
  } }, adapter, { stateDir })
  try {
    const tool = defineTool({ name: 'document', description: 'Fixture', parameters: {},
      output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
      async execute() { return canary },
    })
    tool.finalizeContent = () => [{ type: 'text', text: canary }]
    ctx.tools.register(tool)
    const agent = await createAgent(ctx, id)
    agent.followup(user('Read the document.'))
    await agent.whenIdle()
    expect(adapter.requests).toHaveLength(2)
    expect(JSON.stringify(adapter.requests[1])).toContain(canary)
    expect(JSON.stringify(adapter.requests[1])).toContain('No security scan was completed')
  } finally { await ctx.fiber.dispose(); await rm(stateDir, { recursive: true, force: true }) }
})

it('a canonical cancellation does not stop an independent agent', async () => {
  const stateDir = await mkdtemp(join(tmpdir(), 'patronus-cancel-session-'))
  const adapter = new MockAdapter([textResponse('independent'), textResponse('cancelled session recovered')])
  const ctx = await createHarness({ async scan() { return { status: 'approved' } } }, adapter, { stateDir })
  try {
    let calls = 0
    registerTextTool(ctx, 'document', 'ordinary result', () => { calls++ })
    const cancelled = await createAgent(ctx, 'cancelled')
    const result = await ctx.tools.execute({ callId: ToolCallId('cancelled-call'), name: 'document', arguments: {}, signal: AbortSignal.abort(), agent: cancelled })
    expect(result.isError).toBe(true)
    expect(calls).toBe(0)
    const independent = await createAgent(ctx, 'independent')
    independent.followup(user('Say hello.'))
    await independent.whenIdle()
    cancelled.followup(user('Say hello again.'))
    await cancelled.whenIdle()
    expect(adapter.requests).toHaveLength(2)
  } finally { await ctx.fiber.dispose(); await rm(stateDir, { recursive: true, force: true }) }
})

it('restores the private capability when the same native session is recreated', async () => {
  const stateDir = await mkdtemp(join(tmpdir(), 'patronus-resume-session-'))
  const scanner = new ControlledScanner('pending-original')
  const ctx = await createHarness(scanner, undefined, { stateDir, responseWaitMs: 0 })
  try {
    registerTextTool(ctx, 'document', 'pending-original')
    const id = SessionId(crypto.randomUUID())
    const first = await ctx.agents.create({ sessionId: id, agentOptions: { provider: 'probe', model: 'scripted' } })
    const receipt = lastReceipt(await execute(ctx, 'document', {}, first.agent))
    await first.dispose()
    const second = await ctx.agents.create({ sessionId: id, agentOptions: { provider: 'probe', model: 'scripted' } })
    scanner.complete({ status: 'approved' })
    await new Promise(resolve => setTimeout(resolve, 0))
    const retrieved = await execute(ctx, 'patronus_check_result', { scan_id: receipt.scan_id }, second.agent)
    expect(lastReceipt(retrieved).status).toBe('approved')
    expect(JSON.stringify(retrieved)).toContain('pending-original')
    const other = await createAgent(ctx, 'other')
    expect((await execute(ctx, 'patronus_check_result', { scan_id: receipt.scan_id }, other)).value).toMatchObject({ status: 'invalid_reference', code: 'scan_not_available' })
  } finally { await ctx.fiber.dispose(); await rm(stateDir, { recursive: true, force: true }) }
})

async function createScannerFixture(root: string): Promise<string> {
  const executable = join(root, 'scanner-fixture')
  // A durable protocol fixture with an exclusive directory lock, matching the
  // actual service's ownership constraint. The parent suite tests real Ark.
  await writeFile(executable, `#!/usr/bin/env node
const fs = require('node:fs'); const path = require('node:path');
const root = process.argv[process.argv.indexOf('--state-dir') + 1];
fs.mkdirSync(root, { recursive: true });
const lock = path.join(root, 'exclusive'); fs.closeSync(fs.openSync(lock, 'wx'));
fs.writeFileSync(path.join(root, 'pid'), String(process.pid));
process.on('exit', () => { fs.unlinkSync(lock); }); process.on('SIGTERM', () => process.exit(0));
require('node:readline').createInterface({ input: process.stdin }).on('line', line => {
  const { id, method, params } = JSON.parse(line); let result;
  if (method === 'hello') result = { protocol_version: 1, provider: 'local', ready: true, scanner_version: 'fixture', ark_version: 'fixture', runtime: { response_wait_ms: 500, request_timeout_ms: 30000, scan_timeout_ms: 60000, max_payload_bytes: 10485760 } };
  else if (method === 'submit') { const scan_id = require('node:crypto').randomUUID(); fs.writeFileSync(path.join(root, 'job'), JSON.stringify({ ...params, scan_id })); result = { scan_id, status: 'pending' }; }
  else if (method === 'check') { const job = JSON.parse(fs.readFileSync(path.join(root, 'job'), 'utf8')); result = job.session === params.session && job.scan_id === params.scan_id ? { scan_id: job.scan_id, status: 'approved', result: job.payload } : { scan_id: params.scan_id, status: 'unavailable' }; }
  else result = { status: 'unavailable' };
  process.stdout.write(JSON.stringify({ id, result }) + String.fromCharCode(10));
});
`, { mode: 0o700 })
  return executable
}

it('releases a scanner when its owning native agent is disposed and reopens its store on resume', async () => {
  const root = await mkdtemp(join(tmpdir(), 'patronus-agent-process-'))
  const executable = await createScannerFixture(root)
  const stateDir = join(root, 'state')
  const ctx = await createHarness(undefined, undefined, { stateDir, executable, responseWaitMs: 0 })
  const id = SessionId('owned-session')
  const key = createHash('sha256').update(id).digest('hex')
  const pidPath = join(stateDir, key, 'scanner', 'pid')
  try {
    registerTextTool(ctx, 'document', 'A harmless document.')
    const first = await ctx.agents.create({ sessionId: id, agentOptions: { provider: 'probe', model: 'scripted' } })
    const receipt = lastReceipt(await execute(ctx, 'document', {}, first.agent))
    const pid = Number(await readFile(pidPath, 'utf8'))
    await first.dispose()
    await expect.poll(() => { try { process.kill(pid, 0); return true } catch { return false } }).toBe(false)
    const restored = await ctx.agents.create({ sessionId: id, agentOptions: { provider: 'probe', model: 'scripted' } })
    const retrieved = await execute(ctx, 'patronus_check_result', { scan_id: receipt.scan_id }, restored.agent)
    expect(lastReceipt(retrieved).status).toBe('approved')
    expect(Number(await readFile(pidPath, 'utf8'))).not.toBe(pid)
    await restored.dispose()
  } finally { await ctx.fiber.dispose(); await rm(root, { recursive: true, force: true }) }
})

it('isolates simultaneous host processes in one cwd and resumes a persisted job after process restart', async () => {
  const root = await mkdtemp(join(tmpdir(), 'patronus-host-processes-'))
  const executable = await createScannerFixture(root)
  const driver = join(root, 'host.mjs')
  await writeFile(driver, `
import { SessionState } from ${JSON.stringify(fileURLToPath(new URL('../src/sessions.ts', import.meta.url)))};
const [, , root, id, executable, scanId] = process.argv;
const sessions = new SessionState({ stateDir: root, executable });
const { client } = await sessions.runtime(id, new AbortController().signal);
const session = sessions.capability(id);
const result = scanId ? await client.check({ session, scan_id: scanId }) : await client.submit({ session, direction: 'response', tool: 'document', call_id: 'call', payload: 'DOC-PERSISTED' });
process.stdout.write(JSON.stringify(result) + String.fromCharCode(10));
process.stdin.resume(); process.stdin.once('end', async () => { await sessions.close(); });
`)
  const children: ChildProcessWithoutNullStreams[] = []
  const start = async (id: string, scanId?: string) => {
    const child = spawn(process.execPath, ['--experimental-transform-types', driver, join(root, 'state'), id, executable, ...scanId ? [scanId] : []], { cwd: root, stdio: 'pipe' })
    children.push(child)
    let diagnostics = ''
    child.stderr.on('data', chunk => { diagnostics = (diagnostics + chunk.toString()).slice(-4000) })
    const exited = new Promise<void>((resolve, reject) => child.once('exit', code => code === 0 ? resolve() : reject(new Error('Host fixture exited unsuccessfully.'))))
    // The exit promise is also awaited during cleanup; prevent an early exit
    // becoming an unhandled rejection while the first line is pending.
    void exited.catch(() => {})
    const result = await new Promise<{ status: string; scan_id: string; result?: unknown }>((resolve, reject) => {
      let buffer = ''
      child.once('error', () => reject(new Error('Host fixture failed to start.')))
      child.once('exit', () => { if (!buffer.includes('\n')) reject(new Error(`Host fixture ended before its reply: ${diagnostics}`)) })
      child.stdout.on('data', chunk => { buffer += chunk.toString(); if (buffer.includes('\n')) resolve(JSON.parse(buffer.split('\n')[0]!)) })
    })
    return { result, async stop() { child.stdin.end(); await exited } }
  }
  try {
    const [first, independent] = await Promise.all([start('session-a'), start('session-b')])
    expect(first.result.status).toBe('pending')
    expect(independent.result.status).toBe('pending')
    await first.stop()
    const resumed = await start('session-a', first.result.scan_id)
    expect(resumed.result.status).toBe('approved')
    expect(resumed.result.result).toBe('DOC-PERSISTED')
    await Promise.all([resumed.stop(), independent.stop()])
  } finally {
    for (const child of children) if (child.exitCode === null) child.kill('SIGTERM')
    await rm(root, { recursive: true, force: true })
  }
}, 15000)
