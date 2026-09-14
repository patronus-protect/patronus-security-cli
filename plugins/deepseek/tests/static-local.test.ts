import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { expect, it, vi } from 'vitest'
import { MockAdapter, textResponse, toolCallResponse } from 'harness-test-mock'
import { StaticScanner } from '../src/static.ts'
import { createAgent, createHarness, execute } from './harness.ts'

const executable = process.env.PATRONUS_TEST_SCANNER
if (!executable) throw new Error('Set PATRONUS_TEST_SCANNER to the trusted installed Ark 0.1.7 CLI.')
const signal = () => new AbortController().signal

it('scans clean file/directory/repo and the known dangerous document with installed Ark 0.1.7, without file bytes in model requests', async () => {
  const version = await promisify(execFile)(executable, ['version'])
  expect(version.stdout).toContain('patronus-ark 0.1.7')
  const root = await mkdtemp(join(tmpdir(), 'patronus-static-local-'))
  const target = join(root, 'project')
  await mkdir(target)
  await mkdir(join(target, '.git'))
  const clean = join(target, '--notes $(echo literal); \' "\n.txt')
  const cleanBytes = 'The garden contains three green trees. STATICCLEANMARKER731.'
  await writeFile(clean, cleanBytes)
  // The caller's explicit local config is authoritative, including its scan policy.
  const configPath = join(root, 'local.toml')
  await writeFile(configPath, '[provider]\nmode = "local"\n[ark]\ncategories = ["prompt_injection"]\nmax_level = "l1"\ndownload_files = true\n[output]\ninclude_chunk_content = true\ninclude_evidence_text = true\n[scan]\ninclude_hidden = false\n')
  // Repo configuration must not switch provider, level, downloads, or outputs.
  await writeFile(join(target, '.patronus-security-scanner.toml'), '[provider]\nmode = "api"\napi_base_url = "https://invalid.example"\n[ark]\ncategories = ["threat"]\nmax_level = "l3"\ndownload_files = true\n[output]\ninclude_chunk_content = true\ninclude_evidence_text = true\nroot = "should-not-exist"\n[scan]\ninclude_hidden = true\n')
  const fixtures = process.env.PATRONUS_TEST_FIXTURES_ROOT
  if (!fixtures) throw new Error('Run through scripts/test.mjs --static-local.')
  const dangerous = join(fixtures, 'finance-q2-board-report.txt')
  const results: any[] = []
  const calls = [
    { kind: 'file', path: clean }, { kind: 'directory', path: target },
    { kind: 'repo', path: target }, { kind: 'file', path: dangerous },
  ]
  const adapter = new MockAdapter([
    ...calls.map((args, i) => toolCallResponse(`static-${i}`, 'patronus_scan', args)),
    textResponse('Static scans complete.'),
  ])
  const ctx = await createHarness(undefined, adapter, { executable, configPath })
  ctx.on('tools/result', (exec, result) => { if (exec.name === 'patronus_scan') results.push(result.value) })
  try {
    const agent = await createAgent(ctx)
    agent.followup(createUserMessage({ content: [{ type: 'text', text: 'Scan the selected local targets.' }], source: { kind: 'user' } }))
    await agent.whenIdle()
    expect(adapter.requests).toHaveLength(5)
    expect(results).toHaveLength(4)
    for (const result of results.slice(0, 3)) {
      expect(result).toMatchObject({ status: 'CLEAN', approved: true, categories: ['prompt_injection'], max_level: 'l1', coverage: { complete: true, analyzed_files: 1, skipped_files: 0, failures: 0 } })
    }
    expect(results[3]).toMatchObject({ status: 'FINDINGS', approved: false, coverage: { complete: true, analyzed_files: 1 } })
    expect(results[3].findings_count).toBeGreaterThan(0)
    expect(results[3].findings).toEqual(expect.arrayContaining([expect.objectContaining({ category: 'prompt_injection', level: 'l1' })]))
    const exposed = JSON.stringify([adapter.requests, agent.session.snapshotEvents(), results])
    for (const marker of [cleanBytes, 'STATICCLEANMARKER731', 'EXPECTED_SIGNAL_PI_DOCUMENT_001', 'ignore all previous instructions']) {
      expect(exposed.toLowerCase()).not.toContain(marker.toLowerCase())
    }
    expect(await readdir(target)).not.toContain('should-not-exist')
    expect(await readdir(target)).not.toContain('.patronus-security-scanner')
    console.log('Installed static CLI evidence:', { version: version.stdout.trim(), modelRequests: adapter.requests.length, results })
  } finally { await ctx.fiber.dispose(); await rm(root, { recursive: true, force: true }) }
})

it.each(['webmcp', 'api'])('rejects a host project configured for %s without an explicit configPath', async provider => {
  const root = await mkdtemp(join(tmpdir(), 'patronus-static-provider-'))
  await writeFile(join(root, 'notes.txt'), 'A tree grows in the garden.')
  await writeFile(join(root, '.patronus-security-scanner.toml'), `[provider]\nmode = "${provider}"\napi_base_url = "https://invalid.example"\n`)
  const cwd = vi.spyOn(process, 'cwd').mockReturnValue(root)
  try {
    const result = await new StaticScanner({ executable }, signal()).scan({ kind: 'directory', path: root }, signal())
    expect(result).toMatchObject({ status: 'FAILED', approved: false, reason: 'unsupported_provider' })
    expect(await readdir(root)).not.toContain('.patronus-security-scanner')
  } finally { cwd.mockRestore(); await rm(root, { recursive: true, force: true }) }
})

it('preserves local host project categories and scan options without an explicit configPath', async () => {
  const root = await mkdtemp(join(tmpdir(), 'patronus-static-project-'))
  const target = join(root, 'target')
  await mkdir(target)
  await writeFile(join(target, '.hidden.txt'), 'A tree grows in the garden.')
  await writeFile(join(root, '.patronus-security-scanner.toml'), '[provider]\nmode = "local"\n[ark]\ncategories = ["pii"]\nmax_level = "l1"\ndownload_files = false\n[scan]\ninclude_hidden = true\n')
  const cwd = vi.spyOn(process, 'cwd').mockReturnValue(root)
  try {
    const result = await new StaticScanner({ executable }, signal()).scan({ kind: 'directory', path: target }, signal())
    expect(result).toMatchObject({ status: 'CLEAN', approved: true, categories: ['pii'], coverage: { complete: true, analyzed_files: 1 } })
  } finally { cwd.mockRestore(); await rm(root, { recursive: true, force: true }) }
})

it('returns incomplete coverage for an explicit symlink instead of approving its target', async () => {
  const { symlink } = await import('node:fs/promises')
  const root = await mkdtemp(join(tmpdir(), 'patronus-static-symlink-'))
  const configPath = join(root, 'local.toml')
  await writeFile(configPath, '[provider]\nmode = "local"\n[ark]\nmax_level = "l1"\ndownload_files = false\n[scan]\nfollow_symlinks = false\n')
  await writeFile(join(root, 'notes.txt'), 'A tree grows in the garden.')
  await symlink(join(root, 'notes.txt'), join(root, 'link.txt'))
  const ctx = await createHarness(undefined, undefined, { executable, configPath })
  try {
    const result = await execute(ctx, 'patronus_scan', { kind: 'file', path: join(root, 'link.txt') })
    expect(result.value).toMatchObject({ status: 'INCOMPLETE', approved: false, coverage: { complete: false, skipped_files: 1 } })
  } finally { await ctx.fiber.dispose(); await rm(root, { recursive: true, force: true }) }
})
