import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'

// Hosts may start the bundle through a symlinked path; it must still run instead of
// exiting silently with no hook output.
test('the built bundle answers hooks when started through a symlinked path', { timeout: 30_000 }, t => {
  const bundle = resolve('plugins/claude/scripts/patronus.mjs')
  if (!existsSync(bundle)) return t.skip('built Claude bundle not present')
  const root = mkdtempSync(join(tmpdir(), 'patronus-symlink-'))
  try {
    const link = join(root, 'linked.mjs')
    symlinkSync(bundle, link)
    const input = JSON.stringify({ hook_event_name: 'UserPromptSubmit', session_id: 'symlink-session', cwd: root, prompt: 'patronus status' })
    const run = spawnSync(process.execPath, [link, 'hook', 'claude', 'UserPromptSubmit'], {
      input, encoding: 'utf8', env: { ...process.env, PATRONUS_DATA_DIR: join(root, 'data') }, timeout: 20_000,
    })
    assert.equal(run.status, 0, run.stderr)
    assert.match(run.stdout, /Patronus/, 'hook produced no answer through the symlinked path')
  } finally { rmSync(root, { recursive: true, force: true }) }
})
