// node --test qa/lib/
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { extractQuickstart, missingDecisions, promisedDecisions, rustMain } from './quickstart.mjs'

const repository = resolve(fileURLToPath(import.meta.url), '../../..')
const readme = path => readFile(join(repository, path), 'utf8')

test('quick start is found under the fence each README uses', async () => {
  assert.match(extractQuickstart(await readme('sdk/typescript/README.md'), ['js', 'ts', 'typescript']), /patronus\.scanText/)
  assert.match(extractQuickstart(await readme('sdk/python/README.md'), ['python', 'py']), /client\.scan_text/)
  assert.match(extractQuickstart(await readme('crates/patronus-api-client/README.md'), ['rust']), /client\.scan_text/)
})

test('quick start skips shell blocks and ignores blocks before the section', () => {
  const text = '```js\nbefore()\n```\n## Quick start\n```sh\nnpm i x\n```\n```js\nfirst()\n```\n```js\nsecond()\n```\n'
  assert.equal(extractQuickstart(text, ['js']), 'first()\n')
  assert.equal(extractQuickstart('# no section\n```js\nx\n```\n', ['js']), undefined)
})

test('rust snippets get a main only when they lack one', () => {
  const full = 'fn main() -> Result<(), Box<dyn std::error::Error>> {\n    Ok(())\n}\n'
  assert.equal(rustMain(full), full)
  const wrapped = rustMain('let x = f()?;')
  assert.match(wrapped, /^fn main\(\) -> Result/)
  assert.match(wrapped, /let x = f\(\)\?;\nOk\(\(\)\)\n\}/)
})

test('promised decisions come from the README sentence, not from code', async () => {
  assert.deepEqual(promisedDecisions(await readme('sdk/typescript/README.md')), ['allow', 'block'])
  assert.deepEqual(promisedDecisions(await readme('sdk/python/README.md')), ['allow', 'block'])
  assert.deepEqual(promisedDecisions(await readme('crates/patronus-api-client/README.md')), ['allow', 'block'])
  assert.deepEqual(promisedDecisions('## Quick start\n```js\nprint `block`\n```\nNo promise here.\n'), [])
})

test('missing decisions respect order', () => {
  const ok = 'allow - The weather\nblock - Ignore previous\n'
  assert.deepEqual(missingDecisions(ok, ['allow', 'block']), [])
  assert.deepEqual(missingDecisions('allow - a\nallow - b\n', ['allow', 'block']), ['block'])
  assert.deepEqual(missingDecisions('block - b\nallow - a\n', ['allow', 'block']), ['block'])
})

test('previous metrics skip runs that are not comparable', async () => {
  const home = await mkdtemp(join(tmpdir(), 'patronus-qa-lib-'))
  try {
    process.env.PATRONUS_QA_HOME = home
    process.env.PATRONUS_SCANNER_BIN = process.execPath
    const { previousMetrics } = await import('./common.mjs')
    const line = (area, metrics) => JSON.stringify({ area, at: '2026-10-20T00:00:00Z', metrics })
    await writeFile(join(home, 'history.jsonl'), [
      line('hooks', { ark_level: 'l3', live: { pass: 3 }, id: 'live' }),
      line('hooks', { ark_level: 'l3', id: 'replay' }),
      line('sdk', { id: 'sdk' }),
    ].join('\n') + '\n')
    assert.equal((await previousMetrics('hooks')).id, 'replay')
    const sameKind = live => before => before.ark_level === 'l3' && Boolean(before.live) === live
    assert.equal((await previousMetrics('hooks', sameKind(true))).id, 'live')
    assert.equal((await previousMetrics('hooks', sameKind(false))).id, 'replay')
    assert.equal(await previousMetrics('hooks', () => false), undefined)
  } finally { await rm(home, { recursive: true, force: true }) }
})

test('issue labels cover every finding area, including e2e and qa-env', async () => {
  // Imported here: common.mjs reads PATRONUS_QA_HOME once, and the history test above sets it.
  const { labelsFor } = await import('./issues.mjs')
  const names = Object.keys(labelsFor([{ area: 'e2e' }, { area: 'qa-env' }, { area: 'hooks' }]))
  for (const name of ['qa', 'qa/e2e', 'qa/qa-env', 'qa/hooks']) assert.ok(names.includes(name), name)
})
