// Shared helpers for the QA routine. Node built-ins only.
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises'
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
/** Everything the QA routine keeps outside the repository: QA login, history, run reports. */
export const qaHome = process.env.PATRONUS_QA_HOME ?? join(homedir(), '.patronus-qa')
/** Data dir of the dedicated QA account (`PATRONUS_DATA_DIR=... patronus-security-scanner auth login`). */
export const qaData = join(qaHome, 'data')
export const scanner = process.env.PATRONUS_SCANNER_BIN ?? join(repository, 'target/debug/patronus-security-scanner')
export const thresholds = JSON.parse(readFileSync(join(repository, 'qa/thresholds.json'), 'utf8'))

/** Loads KEY=value lines from ~/.patronus-qa/env without overriding the environment. */
export function loadEnv() {
  const path = join(qaHome, 'env')
  if (!existsSync(path)) return
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line)
    if (match && process.env[match[1]] === undefined) process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2')
  }
}

export function args(argv = process.argv.slice(2)) {
  const options = { dryRun: !argv.includes('--publish'), json: argv.includes('--json'), areas: [] }
  for (let index = 0; index < argv.length; index++) {
    if (argv[index] === '--areas') options.areas = argv[++index].split(',')
    if (argv[index] === '--out') options.out = argv[++index]
    if (argv[index] === '--live') options.live = true
  }
  return options
}

/** Runs a command without a shell; never throws on a non-zero exit. */
export function run(command, argv, { cwd = repository, env = process.env, timeout = 600_000, input } = {}) {
  return new Promise(done => {
    const started = Date.now()
    let stdout = '', stderr = ''
    let child
    try { child = spawn(command, argv, { cwd, env, stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'], detached: true }) }
    catch (error) { done({ code: -1, stdout, stderr: String(error), ms: 0 }); return }
    const timer = setTimeout(() => { try { process.kill(-child.pid, 'SIGKILL') } catch {} }, timeout)
    child.stdout.on('data', part => { stdout += part })
    child.stderr.on('data', part => { stderr += part })
    child.once('error', error => { clearTimeout(timer); done({ code: -1, stdout, stderr: stderr + String(error), ms: Date.now() - started }) })
    child.once('close', (code, signal) => { clearTimeout(timer); done({ code: code ?? (signal ? 128 : -1), signal, stdout, stderr, ms: Date.now() - started }) })
    if (input !== undefined) child.stdin.end(input)
  })
}

export const sha256 = value => createHash('sha256').update(value).digest('hex')

/**
 * One QA finding. `key` must be stable across runs (no timestamps or counts) so the
 * issue upsert can find the open issue again.
 */
export function finding(area, severity, key, title, { evidence = '', suggestion = '', metric } = {}) {
  return { area, severity, fingerprint: `qa:${area}:${sha256(key).slice(0, 16)}`, title, evidence, suggestion, ...(metric ? { metric } : {}) }
}

export const severities = ['critical', 'high', 'medium', 'low']

/** Writes the area report next to the run and appends metrics to the local history. */
export async function report(area, { findings, metrics = {}, checks = [] }, options = {}) {
  const day = new Date().toISOString().slice(0, 10)
  const directory = options.out ?? join(qaHome, 'runs', day)
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const value = { schema: 'patronus.qa.report.v1', area, at: new Date().toISOString(), metrics, checks, findings }
  await writeFile(join(directory, `${area}.json`), JSON.stringify(value, null, 2) + '\n')
  await mkdir(qaHome, { recursive: true, mode: 0o700 })
  await appendFile(join(qaHome, 'history.jsonl'), JSON.stringify({ area, at: value.at, metrics }) + '\n')
  const failed = checks.filter(check => !check.ok).length
  process.stdout.write(`${area}: ${checks.length - failed}/${checks.length} checks ok, ${findings.length} findings -> ${join(directory, area + '.json')}\n`)
  for (const item of findings) process.stdout.write(`  [${item.severity}] ${item.title}\n`)
  return value
}

/** Last recorded metrics for an area, for regression deltas. */
export async function previousMetrics(area) {
  try {
    const lines = (await readFile(join(qaHome, 'history.jsonl'), 'utf8')).trim().split('\n').reverse()
    for (const line of lines) { const entry = JSON.parse(line); if (entry.area === area) return entry.metrics }
  } catch {}
  return undefined
}

export const percentile = (values, p) => {
  if (!values.length) return null
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]
}

export const rate = (part, total) => total ? Math.round((part / total) * 1000) / 1000 : null
