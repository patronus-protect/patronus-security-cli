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
