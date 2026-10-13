#!/usr/bin/env node
// Integration checks: host CLI drift, plugin manifests, local runtime, hosted API, MCP and docs contract.
// Read-only: nothing is installed, enabled or changed on this machine.
//
//   node qa/integrations.mjs [--out DIR]
import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { args, finding, loadEnv, report, repository, run, scanner } from './lib/common.mjs'

loadEnv()
const options = args()
const findings = []
const checks = []
const metrics = {}
const check = (name, ok, detail = '') => { checks.push({ name, ok, detail }); return ok }
const env = { ...process.env, PATH: `${join(homedir(), '.local/bin')}:/opt/homebrew/bin:${process.env.PATH}` }
const key = process.env.PATRONUS_QA_API_KEY
const control = process.env.PATRONUS_QA_CONTROL_URL ?? 'https://control.patronus.studio'

// Host CLI versions against the versions the release gate pins.
const pinned = Object.fromEntries((await readFile(join(repository, '.github/release-host-versions.env'), 'utf8'))
  .split('\n').map(line => line.split('=')).filter(([name, value]) => name && value))
const hostCommands = { codex: ['codex', 'CODEX_RELEASE_VERSION'], claude: ['claude', 'CLAUDE_RELEASE_VERSION'], deepseek: ['dsh', 'DEEPSEEK_RELEASE_VERSION'] }
const semver = text => /(\d+)\.(\d+)\.(\d+)/.exec(text ?? '')?.slice(1).map(Number)
metrics.hosts = {}
for (const [host, [command, variable]] of Object.entries(hostCommands)) {
  const result = await run(command, ['--version'], { env, timeout: 30_000 })
  const installed = result.code === 0 ? semver(result.stdout)?.join('.') : undefined
  const expected = pinned[variable]
  metrics.hosts[host] = { installed: installed ?? null, pinned: expected }
  if (!installed) { check(`${host} CLI available`, false, 'not installed'); continue }
  const [a, b] = [semver(installed), semver(expected)]
  const drift = a[0] !== b[0] ? 'major' : a[1] !== b[1] ? 'minor' : a[2] !== b[2] ? 'patch' : 'none'
  check(`${host} CLI matches release pin`, drift === 'none' || drift === 'patch', `${installed} vs pinned ${expected}`)
  const newer = a[0] - b[0] || a[1] - b[1] || a[2] - b[2]
  if ((drift === 'major' || drift === 'minor') && newer > 0)
    findings.push(finding('integrations', drift === 'major' ? 'high' : 'medium', `host-drift:${host}:${expected}`, `${host} ${installed} is newer than the tested release pin ${expected}`,
      { metric: { installed, pinned: expected }, suggestion: `Run the hook QA (qa/hooks.mjs) against ${host} ${installed}; if it passes, bump ${variable} in .github/release-host-versions.env.` }))
  else if ((drift === 'major' || drift === 'minor') && newer < 0)
    findings.push(finding('qa-env', 'low', `host-outdated:${host}`, `${host} ${installed} on the QA machine is older than the release pin ${expected}`,
      { metric: { installed, pinned: expected }, suggestion: `Update ${host} on the QA machine so the hook QA tests what users get.` }))
}

// Plugin manifests must agree with the CLI version.
const cliVersion = /^version = "(.+)"/m.exec(await readFile(join(repository, 'Cargo.toml'), 'utf8'))[1]
for (const path of ['plugins/claude/.claude-plugin/plugin.json', 'plugins/codex/.codex-plugin/plugin.json', 'plugins/codex-api/.codex-plugin/plugin.json', '.claude-plugin/marketplace.json']) {
  const text = await readFile(join(repository, path), 'utf8')
  const versions = [...text.matchAll(/"version"\s*:\s*"([^"]+)"/g)].map(match => match[1])
  const ok = versions.every(version => version === cliVersion)
  check(`${path} version matches CLI ${cliVersion}`, ok, versions.join(', '))
  if (!ok) findings.push(finding('integrations', 'medium', `manifest-version:${path}`, `${path} declares ${versions.join(', ')} but the CLI is ${cliVersion}`))
}

// Local runtime: probe text and per-host integration status (read-only).
const probe = await run(scanner, ['probe'], { env, timeout: 30_000 })
check('runtime probe emits the fixed text', probe.code === 0 && probe.stdout.startsWith('PATRONUS_RUNTIME_PROBE_V1'), probe.stdout.slice(0, 60))
metrics.status = {}
for (const host of ['claude', 'codex', 'deepseek']) {
  const result = await run(scanner, ['integration', host, 'status', '--format', 'json'], { env, timeout: 60_000 })
  let status
  try { status = JSON.parse(result.stdout) } catch {}
  metrics.status[host] = status?.state ?? 'unreadable'
  check(`${host} integration status readable`, Boolean(status?.reachable ?? status), metrics.status[host])
  if (!status) findings.push(finding('integrations', 'medium', `status-unreadable:${host}`, `integration ${host} status --format json does not return JSON`,
    { evidence: (result.stderr || result.stdout).slice(-1500) }))
}

// Hosted API and MCP endpoint.
async function timed(url, init) {
  const started = Date.now()
  try { const response = await fetch(url, { ...init, signal: AbortSignal.timeout(30_000) }); return { response, ms: Date.now() - started, body: await response.text() } }
  catch (error) { return { error: String(error), ms: Date.now() - started } }
}
const openapi = await timed('https://docs.patronus.studio/openapi.json')
let spec
try { spec = JSON.parse(openapi.body) } catch {}
const pin = JSON.parse(await readFile(join(repository, 'contract/openapi-version.json'), 'utf8'))
metrics.openapi = { published: spec?.info?.version ?? null, pinned: pin.version }
// Concise structural diff of two OpenAPI documents: operations, parameters, responses and component schema properties.
function diffOpenApi(before, after) {
  const lines = []
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)
  const keys = (a, b) => [...new Set([...Object.keys(a ?? {}), ...Object.keys(b ?? {})])].sort()
  const operations = document => Object.fromEntries(Object.entries(document?.paths ?? {}).flatMap(([path, item]) =>
    Object.entries(item ?? {}).filter(([method]) => /^(get|put|post|patch|delete|head|options)$/.test(method)).map(([method, operation]) => [`${method.toUpperCase()} ${path}`, operation])))
  const [oldOps, newOps] = [operations(before), operations(after)]
  for (const name of keys(oldOps, newOps)) {
    const [a, b] = [oldOps[name], newOps[name]]
    if (!a) { lines.push(`+ path ${name}`); continue }
    if (!b) { lines.push(`- path ${name}`); continue }
    const params = operation => Object.fromEntries((operation.parameters ?? []).map(parameter => [`${parameter.in}:${parameter.name}`, parameter]))
    const [oldParams, newParams] = [params(a), params(b)]
    for (const param of keys(oldParams, newParams))
      if (!oldParams[param]) lines.push(`+ param ${name} ${param}`)
      else if (!newParams[param]) lines.push(`- param ${name} ${param}`)
      else if (!same(oldParams[param], newParams[param])) lines.push(`~ param ${name} ${param}`)
    for (const status of keys(a.responses, b.responses))
      if (!a.responses?.[status]) lines.push(`+ response ${name} ${status}`)
      else if (!b.responses?.[status]) lines.push(`- response ${name} ${status}`)
      else if (!same(a.responses[status], b.responses[status])) lines.push(`~ response ${name} ${status}`)
    if (!same(a.requestBody, b.requestBody)) lines.push(`~ requestBody ${name}`)
  }
  const [oldSchemas, newSchemas] = [before?.components?.schemas ?? {}, after?.components?.schemas ?? {}]
  for (const name of keys(oldSchemas, newSchemas)) {
    const [a, b] = [oldSchemas[name], newSchemas[name]]
    if (!a) { lines.push(`+ schema ${name}`); continue }
    if (!b) { lines.push(`- schema ${name}`); continue }
    if (same(a, b)) continue
    let detailed = false
    for (const property of keys(a.properties, b.properties)) {
      const [x, y] = [a.properties?.[property], b.properties?.[property]]
      const required = [(a.required ?? []).includes(property), (b.required ?? []).includes(property)]
      if (!x) lines.push(`+ property ${name}.${property}${required[1] ? ' (required)' : ''}`)
      else if (!y) lines.push(`- property ${name}.${property}`)
      else if (!same(x, y) || required[0] !== required[1])
        lines.push(`~ property ${name}.${property}${required[0] !== required[1] ? (required[1] ? ' (now required)' : ' (now optional)') : ''}`)
      else continue
      detailed = true
    }
    const rest = schema => { const { properties, required, ...other } = schema; return other }
    if (!same(rest(a), rest(b)) || !detailed) lines.push(`~ schema ${name}`)
  }
  return lines
}

if (check('published OpenAPI is reachable', Boolean(spec), openapi.error ?? String(openapi.response?.status))) {
  if (spec.info?.version !== pin.version) {
    let pinned
    try { pinned = JSON.parse(await readFile(join(repository, 'contract/openapi.json'), 'utf8')) } catch {}
    const changes = pinned ? diffOpenApi(pinned, spec) : []
    metrics.openapi.changes = changes.length
    findings.push(finding('integrations', 'medium', `openapi-drift:${pin.version}`, `Published OpenAPI is ${spec.info?.version}; SDKs are pinned to ${pin.version}`,
      { evidence: pinned ? `contract/openapi.json (${pinned.info?.version}) -> published (${spec.info?.version}), ${changes.length} change(s):\n${changes.slice(0, 80).join('\n')}${changes.length > 80 ? `\n... ${changes.length - 80} more` : ''}`
          : 'contract/openapi.json is missing or unreadable; no structural diff available.',
        suggestion: 'Update contract/openapi.json from the published spec, run node contract/validate.mjs, update fixtures and SDKs, then bump contract/openapi-version.json.' }))
  }
} else findings.push(finding('docs', 'high', 'openapi-unreachable', 'https://docs.patronus.studio/openapi.json is not reachable or not JSON', { evidence: openapi.error ?? openapi.body?.slice(0, 500) }))

if (key) {
  const auth = { authorization: `Bearer ${key}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' }
  const init = await timed(`${control}/api/mcp`, { method: 'POST', headers: auth,
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'patronus-qa', version: '1' } } }) })
  const session = init.response?.headers.get('mcp-session-id')
  // The MCP lifecycle requires the initialized notification before any further request.
  await timed(`${control}/api/mcp`, { method: 'POST', headers: { ...auth, ...(session ? { 'mcp-session-id': session } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) })
  const list = await timed(`${control}/api/mcp`, { method: 'POST', headers: { ...auth, ...(session ? { 'mcp-session-id': session } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) })
  const tools = [...(list.body ?? '').matchAll(/"name"\s*:\s*"([^"]+)"/g)].map(match => match[1])
  metrics.mcp = { initialize_ms: init.ms, tools_list_ms: list.ms, tools }
  if (!check('hosted MCP lists tools', list.response?.ok && tools.length > 0, `${tools.length} tools`))
    findings.push(finding('integrations', 'high', 'hosted-mcp', 'Hosted MCP at /api/mcp does not list tools for the QA account',
      { evidence: `initialize: ${init.response?.status ?? init.error}\ntools/list: ${list.response?.status ?? list.error}\n${(list.body ?? '').slice(0, 800)}` }))
} else findings.push(finding('integrations', 'medium', 'qa-key-missing', 'QA API key missing: hosted MCP was not checked',
  { suggestion: 'Add PATRONUS_QA_API_KEY=... to ~/.patronus-qa/env (chmod 600).' }))

// The QA login token lasts 14 days; warn before scheduled live runs start failing. Only expires_at is read.
const credentials = join(process.env.PATRONUS_QA_HOME ?? join(homedir(), '.patronus-qa'), 'data/auth/credentials.json')
let expiresAt
try { expiresAt = Number(JSON.parse(await readFile(credentials, 'utf8')).expires_at) * 1000 } catch {}
const daysLeft = expiresAt ? Math.floor((expiresAt - Date.now()) / 86_400_000) : undefined
metrics.qa_login_days_left = daysLeft ?? null
if (!check('QA data dir signed in', daysLeft !== undefined && daysLeft >= 3, daysLeft === undefined ? 'not signed in' : `${daysLeft} days left`))
  findings.push(finding('integrations', daysLeft !== undefined && daysLeft >= 0 ? 'low' : 'medium', 'qa-login-expiring', daysLeft === undefined ? 'QA account is not signed in' : `QA login expires in ${daysLeft} days`,
  { suggestion: 'From the repository root: PATRONUS_DATA_DIR=$HOME/.patronus-qa/data target/release/patronus-security-scanner auth login (QA account).' }))

await report('integrations', { findings, metrics, checks }, options)
