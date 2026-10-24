// node --test qa/lib/report.test.mjs
import assert from 'node:assert/strict'
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

test('a named report keeps the area report of the same day', async () => {
  const home = await mkdtemp(join(tmpdir(), 'patronus-qa-report-'))
  try {
    process.env.PATRONUS_QA_HOME = home
    process.env.PATRONUS_SCANNER_BIN = process.execPath
    const { report } = await import('./common.mjs')
    const { collect } = await import('./issues.mjs')
    const out = join(home, 'run')
    const finding = fingerprint => ({ area: 'e2e', severity: 'high', fingerprint, title: fingerprint })
    await report('e2e', { findings: [finding('qa:e2e:scripted')], metrics: { mode: 'scripted' } }, { out })
    await report('e2e', { findings: [finding('qa:e2e:live')], metrics: { mode: 'live' } }, { out, name: 'e2e-live' })
    assert.deepEqual((await readdir(out)).sort(), ['e2e-live.json', 'e2e.json'])
    assert.equal(JSON.parse(await readFile(join(out, 'e2e.json'), 'utf8')).metrics.mode, 'scripted')
    assert.equal(JSON.parse(await readFile(join(out, 'e2e-live.json'), 'utf8')).area, 'e2e')
    assert.deepEqual((await collect(out)).map(item => item.fingerprint).sort(), ['qa:e2e:live', 'qa:e2e:scripted'])
    const history = (await readFile(join(home, 'history.jsonl'), 'utf8')).trim().split('\n').map(line => JSON.parse(line))
    assert.deepEqual(history.map(entry => [entry.area, entry.metrics.mode]), [['e2e', 'scripted'], ['e2e', 'live']])
  } finally { await rm(home, { recursive: true, force: true }) }
})

test('grouped findings become one issue with every instance', async () => {
  const home = await mkdtemp(join(tmpdir(), 'patronus-qa-group-'))
  try {
    process.env.PATRONUS_QA_HOME = home
    process.env.PATRONUS_SCANNER_BIN = process.execPath
    const { finding, report } = await import('./common.mjs')
    const { collect } = await import('./issues.mjs')
    const out = join(home, 'run')
    const group = { key: 'e2e:protocol-loop', title: 'Too many protocol calls' }
    await report('e2e', { findings: [
      finding('e2e', 'medium', 'codex:read-readme:protocol-loop', 'codex: read-readme needed 9 protocol calls', { evidence: 'a', group }),
      finding('e2e', 'high', 'cursor:mcp-issue-1:protocol-loop', 'cursor: mcp-issue-1 needed 7 protocol calls', { evidence: 'b', group }),
      finding('e2e', 'low', 'codex:other', 'codex: something else'),
    ] }, { out })
    const items = await collect(out)
    assert.equal(items.length, 2)
    const merged = items.find(item => item.title === group.title)
    assert.equal(merged.severity, 'high')
    assert.equal(merged.fingerprint, finding('e2e', 'low', 'x', 'x', { group }).group.fingerprint)
    assert.deepEqual(merged.instances, ['codex: read-readme needed 9 protocol calls', 'cursor: mcp-issue-1 needed 7 protocol calls'])
    assert.match(merged.evidence, /codex: read-readme needed 9 protocol calls\na/)
  } finally { await rm(home, { recursive: true, force: true }) }
})
