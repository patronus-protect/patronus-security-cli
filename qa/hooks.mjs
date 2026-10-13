#!/usr/bin/env node
// Hook QA: enable hooks in an isolated sandbox, exercise them, measure, then tear everything down.
//
// Hooks are never enabled in the global Claude or Codex configuration. Every layer loads the
// plugin per process (direct bundle calls, `claude --plugin-dir`, a temporary CODEX_HOME), so
// other local routines running at the same time never see Patronus hooks. The global state is
// snapshotted before and verified after the run.
//
//   node qa/hooks.mjs [--quick] [--live] [--out DIR] [--keep]
//
// --quick runs only the replay layer (seconds instead of ~20 minutes).
//
// --live additionally runs a real Claude session (paid model turns) against the QA account in
// ~/.patronus-qa/data. Replay and scripted host suites need no network login.
import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { args, finding, loadEnv, percentile, previousMetrics, qaData, qaHome, rate, report, repository, run, scanner, sha256, thresholds } from './lib/common.mjs'

loadEnv()
const options = { ...args(), keep: process.argv.includes('--keep'), quick: process.argv.includes('--quick') }
const limits = thresholds.hooks
const arkLevel = process.env.PATRONUS_QA_ARK_LEVEL ?? 'l3'
const runId = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14)
const hosts = ['claude', 'codex']
const findings = []
const checks = []
const check = (name, ok, detail = '') => { checks.push({ name, ok, detail }); return ok }
const bin = name => [join(homedir(), '.local/bin', name), `/opt/homebrew/bin/${name}`, `/usr/local/bin/${name}`].find(existsSync) ?? name

// ---------------------------------------------------------------------------------------------
// Global state guard

const globalFiles = [
  '.claude/settings.json', '.claude/plugins/installed_plugins.json', '.claude/plugins/known_marketplaces.json',
  '.codex/config.toml', '.codex/hooks.json',
].map(path => join(homedir(), path))

async function snapshot() {
  const files = {}
  for (const path of globalFiles) files[path] = existsSync(path) ? sha256(await readFile(path)) : null
  const status = {}
  for (const host of hosts) {
    const result = await run(scanner, ['integration', host, 'status', '--format', 'json'], { timeout: 60_000, env: { ...process.env, PATH: `${join(homedir(), '.local/bin')}:${process.env.PATH}` } })
    try { status[host] = JSON.parse(result.stdout).state ?? 'unknown' } catch { status[host] = 'unreadable' }
  }
  return { files, status }
}

// ---------------------------------------------------------------------------------------------
// Sandbox

const sandbox = await mkdtemp(join(process.platform === 'darwin' ? '/private/tmp' : '/tmp', 'patronus-qa-hooks-'))
const replayData = join(sandbox, 'replay-data')
// The broker refuses a state dir inside the session's working directory, so they are siblings.
const work = join(sandbox, 'work')
await mkdir(work, { mode: 0o700 })
const sessions = []
let tornDown = false

async function sandboxEnv(dataDir) {
  await mkdir(dataDir, { recursive: true, mode: 0o700 })
  const config = join(sandbox, 'scanner.toml')
  // Production profile: L3 with the models `assets prepare` placed in ~/.patronus-qa/models.
  if (!existsSync(config)) await writeFile(config, `[provider]\nmode="local"\n[ark]\ncategories=["prompt_injection","pii","dlp"]\nmax_level=${JSON.stringify(arkLevel)}\ndownload_files=false\nmodel_dir=${JSON.stringify(join(qaHome, 'models'))}\n`)
  return {
    ...process.env,
    PATH: `${join(homedir(), '.local/bin')}:${process.env.PATH}`,
    PATRONUS_HOOK_TRACE: '1',
    PATRONUS_DATA_DIR: dataDir,
    PATRONUS_SCANNER_BIN: scanner,
    PATRONUS_PROOF_SCANNER: scanner,
    PATRONUS_CONFIG: config,
    PATRONUS_NATIVE_STATE_DIR: join(sandbox, 'state'),
    PATRONUS_PLUGIN_SETTINGS: join(sandbox, 'plugins.json'),
    PATRONUS_RESPONSE_WAIT_MS: '60000',
  }
}

const hook = (host, event, input, env) =>
  run(process.execPath, [join(repository, 'plugins', host, 'scripts/patronus.mjs'), 'hook', host, event], { env, input: JSON.stringify(input), timeout: 120_000 })

async function teardown() {
  if (tornDown) return
  tornDown = true
  // Close every broker this run started; a closed session stops its daemon.
  const env = await sandboxEnv(replayData).catch(() => process.env)
  await Promise.all(sessions.map(({ host, session }) =>
    hook(host, host === 'claude' ? 'SessionEnd' : 'Stop', { hook_event_name: host === 'claude' ? 'SessionEnd' : 'Stop', session_id: session, cwd: work }, env).catch(() => {})))
  if (!options.keep) await rm(sandbox, { recursive: true, force: true })
}

for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.once(signal, () => { teardown().finally(() => process.exit(130)) })

// ---------------------------------------------------------------------------------------------
// Journal reading

async function journal(dataDir, since = 0) {
  const events = []
  const directory = join(dataDir, 'protocol')
  if (!existsSync(directory)) return events
  for (const name of (await readdir(directory)).filter(name => name.endsWith('.jsonl'))) {
    for (const line of (await readFile(join(directory, name), 'utf8')).split('\n')) {
      if (!line.trim()) continue
      try { const event = JSON.parse(line).event; if (Date.parse(event.timestamp) >= since) events.push(event) } catch {}
    }
  }
  return events
}

const sessionHash = (host, session) => `sha256:${sha256(JSON.stringify([host, session]))}`

/** Success, error, timeout and latency per host:hook_event from hook_started/hook_completed pairs. */
function hookMetrics(events) {
  const groups = {}
  const group = event => (groups[`${event.host}:${event.hook_event}`] ??= { started: 0, completed: 0, outcomes: {}, decisions: {}, durations: [], errors: {} })
  for (const event of events) {
    if (event.event === 'hook_started') group(event).started++
    if (event.event !== 'hook_completed') continue
    const entry = group(event)
    entry.completed++
    entry.outcomes[event.outcome] = (entry.outcomes[event.outcome] ?? 0) + 1
    entry.decisions[event.decision] = (entry.decisions[event.decision] ?? 0) + 1
    if (typeof event.duration_ms === 'number') entry.durations.push(event.duration_ms)
    if (event.error_code) entry.errors[event.error_code] = (entry.errors[event.error_code] ?? 0) + 1
  }
  const result = {}
  for (const [key, entry] of Object.entries(groups)) {
    const bad = (entry.outcomes.error ?? 0) + (entry.outcomes.inactive ?? 0)
    result[key] = {
      invocations: entry.started,
      success_rate: rate(entry.completed - bad - (entry.outcomes.degraded ?? 0), entry.started),
      error_rate: rate(bad, entry.started),
      degraded_rate: rate(entry.outcomes.degraded ?? 0, entry.started),
      timeout_rate: rate(Math.max(0, entry.started - entry.completed), entry.started),
      override_rate: rate(entry.outcomes.override ?? 0, entry.completed),
      p50_ms: percentile(entry.durations, 50),
      p95_ms: percentile(entry.durations, 95),
      decisions: entry.decisions,
      errors: entry.errors,
    }
  }
  return result
}

// ---------------------------------------------------------------------------------------------
// Layer 1: deterministic replay of the corpus through the built hook bundles

const visibleText = output => {
  const texts = []
  const visit = (value, key) => {
    // Receipts (JSON) are model-facing data, not messages a person reads.
    if (typeof value === 'string' && ['systemMessage', 'additionalContext', 'reason', 'permissionDecisionReason'].includes(key) && !value.trimStart().startsWith('{')) texts.push(value)
    else if (value && typeof value === 'object') for (const [child, item] of Object.entries(value)) visit(item, child)
  }
  visit(output)
  return texts
}

async function replay() {
  const corpus = JSON.parse(await readFile(join(repository, 'qa/hooks/corpus.json'), 'utf8')).cases
  const env = await sandboxEnv(replayData)
  const results = []
  const coldStart = {}
  // One session per host, like a real chat: the first call pays the broker start, the rest are warm.
  for (const host of hosts) {
    const session = `qa-${runId}-${host}`
    sessions.push({ host, session })
    const warmup = await hook(host, 'PostToolUse', { hook_event_name: 'PostToolUse', session_id: session, cwd: work, tool_name: 'Read', tool_use_id: 'call-warmup', tool_input: {}, tool_response: 'warm-up' }, env)
    coldStart[host] = warmup.ms
    for (const item of corpus) {
      const text = item.text.repeat(item.repeat ?? 1)
      const input = { hook_event_name: item.event, session_id: session, cwd: work,
        ...(item.event === 'UserPromptSubmit' ? { prompt: text } : { tool_name: item.tool, tool_use_id: `call-${item.id}`, tool_input: {}, tool_response: text }) }
      const result = await hook(host, item.event, input, env)
      let output = {}
      try { output = JSON.parse(result.stdout.trim() || '{}') } catch {}
      results.push({ host, item, session, code: result.code, ms: result.ms, output, raw: result.stdout })
    }
  }
  const events = await journal(replayData)
  const completed = Object.fromEntries(hosts.map(host => [host, events
    .filter(event => event.event === 'hook_completed' && event.session_id === sessionHash(host, `qa-${runId}-${host}`))
    .sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp)).slice(1)]))
  const rows = results.map(entry => {
    const done = completed[entry.host][results.filter(other => other.host === entry.host).indexOf(entry)]
    const pending = entry.raw.includes('\\"status\\":\\"pending\\"') || entry.raw.includes('"status":"pending"')
    const verdict = !done || entry.code !== 0 ? 'no_trace'
      : ['error', 'inactive', 'degraded'].includes(done.outcome) ? 'unscanned'
      : pending ? 'pending'
      : done.decision === 'allow' ? 'pass' : 'flag'
    return { host: entry.host, id: entry.item.id, category: entry.item.category, event: entry.item.event, expect: entry.item.expect, verdict,
      decision: done?.decision, outcome: done?.outcome, error_code: done?.error_code, ms: entry.ms, messages: visibleText(entry.output) }
  })
  return { rows, events, coldStart }
}

function detectionMetrics(rows, coldStart) {
  const metrics = {}
  for (const host of hosts) {
    const own = rows.filter(row => row.host === host)
    const benign = own.filter(row => row.expect === 'pass')
    const perCategory = {}
    for (const category of [...new Set(own.filter(row => row.expect === 'flag').map(row => row.category))]) {
      const cases = own.filter(row => row.category === category)
      perCategory[category] = rate(cases.filter(row => row.verdict === 'flag').length, cases.length)
    }
    metrics[host] = {
      recall: perCategory,
      false_positive_rate: rate(benign.filter(row => row.verdict === 'flag').length, benign.length),
      unscanned_rate: rate(own.filter(row => ['unscanned', 'no_trace'].includes(row.verdict)).length, own.length),
      pending_rate: rate(own.filter(row => row.verdict === 'pending').length, own.length),
      cold_start_ms: coldStart[host],
      p95_hook_ms: percentile(own.map(row => row.ms), 95),
      max_message_chars: Math.max(0, ...own.flatMap(row => row.messages.map(text => text.length))),
    }
  }
  return metrics
}

// ---------------------------------------------------------------------------------------------
// Layer 1b: selective PII disclosure against the runtime at the QA Ark level

/** One private runtime per run; hook paths are covered by the host suites. */
async function disclosure() {
  const corpus = JSON.parse(await readFile(join(repository, 'qa/hooks/disclosure.json'), 'utf8')).cases
  await sandboxEnv(replayData)
  const child = spawn(scanner, ['serve', '--stdio', '--config', join(sandbox, 'scanner.toml'), '--state-dir', join(sandbox, 'disclosure-state')], { stdio: ['pipe', 'pipe', 'ignore'] })
  const waiting = new Map()
  let next = 0
  createInterface({ input: child.stdout }).on('line', line => { try { const reply = JSON.parse(line); waiting.get(reply.id)?.(reply); waiting.delete(reply.id) } catch {} })
  const rpc = (method, params) => new Promise(resolve => { const id = `q${++next}`; waiting.set(id, resolve); child.stdin.write(JSON.stringify({ id, method, params }) + '\n') })
  const settle = async (method, params) => {
    const deadline = Date.now() + 180_000
    for (;;) {
      const reply = await rpc(method, params)
      if (reply.error || reply.result?.status !== 'pending' || Date.now() > deadline) return reply.result ?? { status: reply.error?.code ?? 'error' }
      await new Promise(done => setTimeout(done, 200))
    }
  }
  const session = `qa-disclosure-${runId}-${'0'.repeat(16)}`
  const rows = []
  try {
    for (const item of corpus) {
      const started = Date.now()
      const submitted = (await rpc('submit', { session, direction: 'response', tool: 'Read', call_id: item.id, payload: item.text })).result
      const scan = await settle('check', { session, scan_id: submitted.scan_id })
      const offer = scan.status === 'dangerous' ? (await rpc('prepare_disclosure', { session, scan_id: submitted.scan_id, reveal_pii: item.reveal })).result : { status: 'not_dangerous' }
      const offered = Date.now()
      const view = offer.grant_id ? await settle('read_disclosed', { session, scan_id: submitted.scan_id, grant_id: offer.grant_id }) : undefined
      const text = typeof view?.result === 'string' ? view.result : JSON.stringify(view?.result ?? '')
      const applied = view?.disclosure?.applied === true
      rows.push({
        id: item.id, expect: item.expect, scan: scan.status, offer: offer.status, counts: offer.counts ?? null,
        outcome: applied ? 'applied' : view ? (view.disclosure ? 'fallback' : view.status) : offer.status,
        leaked: item.masked.filter(value => text.includes(value)),
        missing: applied ? item.visible.filter(value => !text.includes(value)) : [],
        reveal_ms: view ? Date.now() - offered : null, total_ms: Date.now() - started,
      })
    }
  } finally { child.kill() }
  const expected = rows.filter(row => row.expect === 'applied')
  return { rows, metrics: {
    applied_rate: rate(expected.filter(row => row.outcome === 'applied').length, expected.length),
    leaks: rows.reduce((sum, row) => sum + row.leaked.length, 0),
    p95_reveal_ms: percentile(rows.flatMap(row => row.reveal_ms ?? []), 95),
    outcomes: Object.fromEntries(rows.map(row => [row.id, row.outcome])),
  } }
}

function evaluateDisclosure({ rows, metrics }) {
  check('disclosure never reveals masked values', metrics.leaks === 0, `${metrics.leaks} leaked values`)
  for (const row of rows) {
    if (row.leaked.length)
      findings.push(finding('hooks', 'critical', `disclosure-leak:${row.id}`, `Disclosure case ${row.id} revealed values that must stay masked`,
        { evidence: JSON.stringify(row), suggestion: 'Inspect the lock set in src/runtime/disclosure.rs for this case.' }))
    if (row.expect === 'nothing' && row.offer === 'confirmation_required')
      findings.push(finding('hooks', 'high', `disclosure-offer:${row.id}`, `Disclosure case ${row.id} offered types that are not in the text`, { evidence: JSON.stringify(row) }))
    if (row.expect === 'applied' && (row.outcome !== 'applied' || row.missing.length))
      findings.push(finding('hooks', 'medium', `disclosure-miss:${row.id}:${arkLevel}`, `Disclosure case ${row.id} was not revealed at Ark ${arkLevel} (${row.outcome})`,
        { evidence: JSON.stringify(row), suggestion: 'Only exact L1 spans are revealable; an L2/L3 or re-scan mismatch falls back to the mask. Check which level classified the case.' }))
  }
}

// ---------------------------------------------------------------------------------------------
// Layer 2: scripted host suites (real host CLIs, scripted model, isolated config)

function tapCounts(stdout) {
  const value = key => Number((new RegExp(`^# ${key} (\\d+)`, 'm').exec(stdout) ?? [])[1] ?? 0)
  return { pass: value('pass'), fail: value('fail'), skipped: value('skipped') }
}

async function hostSuites() {
  const out = {}
  const claudeEnv = { ...await sandboxEnv(join(sandbox, 'claude-suite')), PATRONUS_CLAUDE_BINARY: bin('claude') }
  const claude = await run(process.execPath, ['--test', '--test-reporter=tap', 'plugins/claude/tests/claude-host.test.mjs', 'plugins/claude/tests/claude-runtime.test.mjs', 'plugins/claude/tests/chat-control.test.mjs'],
    { env: claudeEnv, timeout: 900_000 })
  out.claude = { ...tapCounts(claude.stdout), code: claude.code, ms: claude.ms, tail: (claude.stdout + claude.stderr).split('\n').filter(line => /^not ok|Error|assert/i.test(line)).slice(0, 30).join('\n') }

  const codexRoot = join(repository, 'plugins/codex')
  const codexEnv = { ...await sandboxEnv(join(sandbox, 'codex-suite')), PATRONUS_CODEX_BIN: bin('codex'),
    PATRONUS_CODEX_PLUGIN_ROOT: codexRoot, PATRONUS_CODEX_PLUGIN_BUNDLE: join(codexRoot, 'scripts/patronus.mjs') }
  const reportDir = join(sandbox, 'codex-e2e')
  const codex = await run(process.execPath, ['tests/release-e2e/run.mjs', '--host', 'codex', '--out', reportDir], { env: codexEnv, timeout: 1_200_000 })
  let e2e
  try { e2e = JSON.parse(await readFile(join(reportDir, 'report.json'), 'utf8')) } catch {}
  const flows = e2e?.results ?? []
  const reveal = await run(process.execPath, ['--test', '--test-reporter=tap', 'plugins/codex/tests/reveal.test.mjs'], { env: { ...codexEnv, PATRONUS_SCANNER_BIN: scanner }, timeout: 600_000 })
  out['codex-disclosure'] = { ...tapCounts(reveal.stdout), code: reveal.code, ms: reveal.ms, tail: (reveal.stdout + reveal.stderr).split('\n').filter(line => /^not ok|Error|assert/i.test(line)).slice(0, 30).join('\n') }
  out.codex = { pass: flows.filter(flow => flow.status === 'PASS').length, fail: flows.filter(flow => flow.status !== 'PASS').length, code: codex.code, ms: codex.ms,
    tail: (codex.stdout + codex.stderr).split('\n').slice(-30).join('\n') }
  // The suites build their own isolated environments and deliberately simulate outages, so their
  // journals are neither reachable nor representative; they count as pass/fail only.
  return { suites: out }
}

// ---------------------------------------------------------------------------------------------
// Layer 3 (opt-in): real Claude session against the QA account

async function live() {
  if (!existsSync(join(qaData, 'auth/credentials.json'))) {
    findings.push(finding('hooks', 'medium', 'live-login-missing', 'QA account is not signed in for live hook runs',
      { suggestion: `Run once from the repository root: PATRONUS_DATA_DIR=${qaData} target/release/patronus-security-scanner auth login (with the QA account).` }))
    return undefined
  }
  const since = Date.now()
  const env = { ...await sandboxEnv(qaData), PATRONUS_CLAUDE_LIVE: '1', PATRONUS_CLAUDE_BINARY: bin('claude') }
  delete env.PATRONUS_CONFIG // the live run uses the QA account's hybrid configuration
  const result = await run(process.execPath, ['--test', '--test-reporter=tap', 'plugins/claude/tests/claude-live.test.mjs'], { env, timeout: 300_000 })
  return { ...tapCounts(result.stdout), code: result.code, ms: result.ms, events: await journal(qaData, since),
    tail: (result.stdout + result.stderr).split('\n').filter(line => /^not ok|inspect|Error/i.test(line)).slice(0, 20).join('\n') }
}

// ---------------------------------------------------------------------------------------------
// Evaluation

function evaluate({ detection, hookStats, suites, liveRun, previous }) {
  for (const [host, metric] of Object.entries(detection)) {
    for (const [category, recall] of Object.entries(metric.recall)) {
      const minimum = limits.min_recall[category]
      if (minimum !== undefined && recall !== null && recall < minimum)
        findings.push(finding('hooks', category === 'injection' ? 'high' : 'medium', `recall:${host}:${category}`,
          `${host}: ${category} detection below target (${recall} < ${minimum})`,
          { metric: { recall }, evidence: JSON.stringify(metric, null, 2), suggestion: 'Inspect missed corpus cases in the run report (verdict=pass with expect=flag) and the scanner categories in the QA scanner config.' }))
    }
    if (metric.false_positive_rate > limits.max_false_positive_rate)
      findings.push(finding('hooks', 'medium', `fp:${host}`, `${host}: benign tool results are withheld (false positive rate ${metric.false_positive_rate})`,
        { metric: { false_positive_rate: metric.false_positive_rate }, suggestion: 'Benign content should reach the model unchanged; check which benign corpus cases were flagged.' }))
    if (metric.unscanned_rate > 0)
      findings.push(finding('hooks', 'high', `unscanned:${host}`, `${host}: hooks completed without a scan (rate ${metric.unscanned_rate})`,
        { metric: { unscanned_rate: metric.unscanned_rate }, suggestion: 'See error codes in the run report; fail-open paths should be rare outside of outages.' }))
    if (metric.pending_rate > 0)
      findings.push(finding('hooks', 'low', `pending:${host}`, `${host}: scans still pending after 60s wait (rate ${metric.pending_rate})`,
        { metric: { pending_rate: metric.pending_rate } }))
    if (metric.cold_start_ms > limits.max_cold_start_ms)
      findings.push(finding('ux', 'medium', `cold-start:${host}`, `${host}: first hook of a session takes ${metric.cold_start_ms} ms`,
        { metric: { cold_start_ms: metric.cold_start_ms }, suggestion: 'The first tool result of every new chat waits for the broker and scanner start; consider starting the broker at SessionStart.' }))
    if (metric.max_message_chars > limits.max_message_chars)
      findings.push(finding('ux', 'low', `message-length:${host}`, `${host}: hook message exceeds ${limits.max_message_chars} characters (${metric.max_message_chars})`,
        { suggestion: 'Long hook messages crowd the agent context and are hard for users to scan; shorten or move details behind a command.' }))
  }
  for (const [key, stat] of Object.entries(hookStats)) {
    const event = key.split(':')[1]
    if (stat.error_rate > limits.max_error_rate)
      findings.push(finding('hooks', 'high', `errors:${key}`, `${key}: hook error rate ${stat.error_rate}`, { metric: stat, evidence: JSON.stringify(stat.errors) }))
    if (stat.timeout_rate > limits.max_timeout_rate)
      findings.push(finding('hooks', 'high', `timeouts:${key}`, `${key}: hooks started but never completed (rate ${stat.timeout_rate})`,
        { metric: stat, suggestion: 'A start without completion means the host killed the hook (timeout) or the process crashed.' }))
    const budget = limits.max_p95_ms[event]
    if (budget && stat.p95_ms > budget)
      findings.push(finding('hooks', 'medium', `latency:${key}`, `${key}: p95 latency ${stat.p95_ms} ms exceeds ${budget} ms`, { metric: { p95_ms: stat.p95_ms } }))
    const before = previous?.hooks?.[key]
    // A broken previous run (all errors, near-zero latency) is no baseline.
    if (before?.p95_ms && before.error_rate <= limits.max_error_rate && stat.p95_ms > before.p95_ms * limits.regression_ratio && stat.p95_ms > 200)
      findings.push(finding('hooks', 'medium', `latency-regression:${key}`, `${key}: p95 latency regressed from ${before.p95_ms} to ${stat.p95_ms} ms`, { metric: { p95_ms: stat.p95_ms } }))
  }
  for (const [host, suite] of Object.entries(suites)) {
    check(`${host} scripted host suite`, suite.code === 0 && suite.fail === 0, `${suite.pass} pass, ${suite.fail} fail`)
    if (suite.code !== 0 || suite.fail > 0)
      findings.push(finding('hooks', 'high', `suite:${host}`, `${host}: scripted host suite fails against the locally installed ${host} CLI`,
        { evidence: suite.tail, suggestion: `Compare the local ${host} version with .github/release-host-versions.env; a host update may have changed the hook contract.` }))
  }
  if (liveRun) {
    check('claude live session', liveRun.code === 0 && liveRun.fail === 0, `${liveRun.pass} pass, ${liveRun.fail} fail`)
    if (liveRun.code !== 0 || liveRun.fail > 0)
      findings.push(finding('hooks', 'high', 'live:claude', 'Real Claude session does not complete the Patronus acceptance scenarios', { evidence: liveRun.tail }))
  }
}

// ---------------------------------------------------------------------------------------------

const before = await snapshot()
for (const host of hosts) {
  check(`${host} hooks globally off before run`, before.status[host] !== 'active', before.status[host])
  if (before.status[host] === 'active')
    findings.push(finding('hooks', 'high', `global-active:${host}`, `Patronus ${host} plugin is globally enabled on the QA machine`,
      { suggestion: `Other local routines must run without hooks. Run: patronus-security-scanner integration ${host} disable` }))
}
let metrics = {}
try {
  const { rows, events: replayEvents, coldStart } = await replay()
  const detection = detectionMetrics(rows, coldStart)
  const disclosed = await disclosure()
  evaluateDisclosure(disclosed)
  const { suites } = options.quick ? { suites: {} } : await hostSuites()
  const liveRun = options.live ? await live() : undefined
  const hookStats = hookMetrics([...replayEvents, ...(liveRun?.events ?? [])])
  const previous = await previousMetrics('hooks')
  evaluate({ detection, hookStats, suites, liveRun, previous: previous?.ark_level === arkLevel ? previous : undefined })
  metrics = { ark_level: arkLevel, detection, disclosure: { ...disclosed.metrics, rows: disclosed.rows }, hooks: hookStats, suites: Object.fromEntries(Object.entries(suites).map(([host, suite]) => [host, { pass: suite.pass, fail: suite.fail, ms: suite.ms }])),
    ...(liveRun ? { live: { pass: liveRun.pass, fail: liveRun.fail, ms: liveRun.ms } } : {}), replay: rows.map(({ messages, ...row }) => row) }
} finally {
  await teardown()
}
const after = await snapshot()
const changed = Object.keys(before.files).filter(path => before.files[path] !== after.files[path])
check('global host config unchanged', changed.length === 0, changed.join(', '))
if (changed.length)
  findings.push(finding('hooks', 'critical', `global-changed:${changed.join(',')}`, 'Global host configuration changed during the hook QA run',
    { evidence: changed.join('\n'), suggestion: 'The run must only load hooks per process. Another routine may also have changed these files; verify manually before restoring anything.' }))
for (const host of hosts) check(`${host} integration state unchanged`, before.status[host] === after.status[host], `${before.status[host]} -> ${after.status[host]}`)

await report('hooks', { findings, metrics, checks }, options)
