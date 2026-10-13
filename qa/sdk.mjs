#!/usr/bin/env node
// SDK smoke test from a new user's point of view: install the *published* packages into empty
// directories and run the README quick starts verbatim against the QA account.
//
//   node qa/sdk.mjs [--out DIR]
//
// Needs PATRONUS_QA_API_KEY (environment or ~/.patronus-qa/env) for the live calls; without it
// only the registry checks run.
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { args, finding, loadEnv, report, repository, run, thresholds } from './lib/common.mjs'

loadEnv()
const options = args()
const findings = []
const checks = []
const metrics = {}
const check = (name, ok, detail = '') => { checks.push({ name, ok, detail }); return ok }
const key = process.env.PATRONUS_QA_API_KEY

const sdks = [
  { id: 'typescript', registry: 'npm', name: '@patronus-protect/api-client', readme: 'sdk/typescript/README.md', fence: 'ts',
    version: async () => JSON.parse(await readFile(join(repository, 'sdk/typescript/package.json'), 'utf8')).version,
    published: async () => (await (await fetch('https://registry.npmjs.org/@patronus-protect%2Fapi-client/latest')).json()).version },
  { id: 'python', registry: 'PyPI', name: 'patronus-api-client', readme: 'sdk/python/README.md', fence: 'python',
    version: async () => /^version = "(.+)"/m.exec(await readFile(join(repository, 'sdk/python/pyproject.toml'), 'utf8'))[1],
    published: async () => (await (await fetch('https://pypi.org/pypi/patronus-api-client/json')).json()).info.version },
  { id: 'rust', registry: 'crates.io', name: 'patronus-api-client', readme: 'crates/patronus-api-client/README.md', fence: 'rust',
    version: async () => /^version = "(.+)"/m.exec(await readFile(join(repository, 'crates/patronus-api-client/Cargo.toml'), 'utf8'))[1],
    published: async () => (await (await fetch('https://crates.io/api/v1/crates/patronus-api-client', { headers: { 'user-agent': 'patronus-qa (team@patronus.studio)' } })).json()).crate.max_stable_version },
]

/** The first fenced block in the README's quick start: what a new user copies first. */
async function quickstart(sdk) {
  const text = await readFile(join(repository, sdk.readme), 'utf8')
  const section = text.slice(text.indexOf('## Quick start'))
  return new RegExp('```' + sdk.fence + '\\n([\\s\\S]*?)```').exec(section)?.[1]
}

// A one-page PDF so quick starts that upload `contract.pdf` have something to send.
const pdf = '%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]/Contents 4 0 R/Resources<<>>>>endobj 4 0 obj<</Length 44>>stream\nBT /F1 12 Tf 20 100 Td (Patronus QA) Tj ET\nendstream endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n'

async function runQuickstart(sdk, code, directory, env) {
  const files = [...code.matchAll(/["']([\w.-]+\.(?:pdf|txt|docx))["']/g)].map(match => match[1])
  for (const file of files) await writeFile(join(directory, file), file.endsWith('.pdf') ? pdf : 'Patronus QA appendix.\n')
  const steps = []
  if (sdk.id === 'typescript') {
    steps.push(['npm', ['init', '-y']], ['npm', ['install', sdk.name]])
    await writeFile(join(directory, 'quickstart.mts'), code + '\nconsole.log(JSON.stringify({ status: result.status }))\n')
    steps.push([process.execPath, ['quickstart.mts']])
  } else if (sdk.id === 'python') {
    steps.push(['python3', ['-m', 'venv', '.venv']], ['.venv/bin/python', ['-m', 'pip', 'install', '-q', sdk.name]])
    await writeFile(join(directory, 'quickstart.py'), code + '\nprint({"status": getattr(result, "status", None)})\n')
    steps.push(['.venv/bin/python', ['quickstart.py']])
  } else {
    steps.push(['cargo', ['init', '-q', '--name', 'quickstart']], ['cargo', ['add', '-q', sdk.name]])
    // Snippets with `?` need a fallible main; a reader has to add it, so it is noted below.
    await writeFile(join(directory, 'src/main.rs.tmp'), `fn main() -> Result<(), Box<dyn std::error::Error>> {\n${code}\nprintln!("{{\\"status\\":\\"{}\\"}}", result.status);\nOk(())\n}\n`)
    steps.push(['mv', ['src/main.rs.tmp', 'src/main.rs']], ['cargo', ['run', '-q']])
  }
  const started = Date.now()
  for (const [command, argv] of steps) {
    const result = await run(command, argv, { cwd: directory, env, timeout: 600_000 })
    if (result.code !== 0) return { ok: false, step: [command, ...argv].join(' '), output: (result.stderr || result.stdout).slice(-3000), ms: Date.now() - started, files }
  }
  return { ok: true, ms: Date.now() - started, files }
}

for (const sdk of sdks) {
  const local = await sdk.version()
  let published
  try { published = await sdk.published() } catch {}
  metrics[sdk.id] = { repo_version: local, published_version: published ?? null }
  if (check(`${sdk.id} published on ${sdk.registry}`, Boolean(published), published ?? 'not found')) {
    if (published !== local) findings.push(finding('sdk', 'medium', `version-drift:${sdk.id}`, `${sdk.id} SDK: ${sdk.registry} has ${published}, repository is at ${local}`,
      { metric: { published, local }, suggestion: 'Publish the current version or align the README with the published API.' }))
  } else findings.push(finding('sdk', 'high', `unpublished:${sdk.id}`, `${sdk.id} SDK ${sdk.name} is not installable from ${sdk.registry}`,
    { suggestion: `The README tells users to install it from ${sdk.registry}.` }))

  const code = await quickstart(sdk)
  if (!check(`${sdk.id} README has a quick start`, Boolean(code))) {
    findings.push(finding('docs', 'medium', `no-quickstart:${sdk.id}`, `${sdk.id} SDK README has no runnable quick start`))
    continue
  }
  if (!key || !published) continue
  const directory = await mkdtemp(join(tmpdir(), `patronus-qa-sdk-${sdk.id}-`))
  try {
    const env = { ...process.env, PATRONUS_API_KEY: key }
    const result = await runQuickstart(sdk, code, directory, env)
    metrics[sdk.id].quickstart_ms = result.ms
    metrics[sdk.id].quickstart_ok = result.ok
    check(`${sdk.id} quick start runs from a fresh install`, result.ok, result.step ?? `${result.ms} ms`)
    if (!result.ok) findings.push(finding('sdk', 'high', `quickstart:${sdk.id}`, `${sdk.id} SDK quick start fails from a fresh install`,
      { evidence: `step: ${result.step}\n\n${result.output.replaceAll(key, '***')}`, suggestion: 'Fix the README snippet or the package so the first copied example works.' }))
    else if (result.ms > thresholds.sdk.max_quickstart_seconds * 1000)
      findings.push(finding('sdk', 'low', `quickstart-slow:${sdk.id}`, `${sdk.id} SDK quick start takes ${Math.round(result.ms / 1000)} s including install`))
    if (result.files.length) findings.push(finding('ux', 'low', `quickstart-files:${sdk.id}`, `${sdk.id} SDK quick start needs local files a new user does not have (${result.files.join(', ')})`,
      { suggestion: 'Lead with scanText / scan_text so the first example runs without preparation; show file uploads second.' }))
    if (sdk.id === 'rust' && /\?/.test(code) && !/fn main/.test(code)) findings.push(finding('ux', 'low', 'quickstart-main:rust', 'Rust quick start uses `?` outside a function and does not compile when pasted into main.rs',
      { suggestion: 'Show a complete `fn main() -> Result<(), Box<dyn std::error::Error>>` example.' }))
  } finally { await rm(directory, { recursive: true, force: true }) }
}

if (!key) findings.push(finding('sdk', 'medium', 'qa-key-missing', 'QA API key missing: SDK quick starts were not executed',
  { suggestion: 'Add PATRONUS_QA_API_KEY=... to ~/.patronus-qa/env (chmod 600).' }))

await report('sdk', { findings, metrics, checks }, options)
