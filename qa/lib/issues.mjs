// Upserts QA findings as GitHub issues. Without --publish nothing leaves the machine.
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { args, qaHome, run, severities } from './common.mjs'

const labels = { qa: '5319e7', 'qa/hooks': 'c5def5', 'qa/e2e': 'c5def5', 'qa/sdk': 'c5def5', 'qa/docs': 'c5def5', 'qa/dashboard': 'c5def5', 'qa/integrations': 'c5def5', 'qa/ux': 'c5def5' }

/** Every label an upsert needs: the fixed set plus `qa/<area>` for areas it does not list (e2e, qa-env, …). */
export function labelsFor(findings) {
  const wanted = { ...labels }
  for (const item of findings) wanted[`qa/${item.area}`] ??= labels['qa/hooks']
  return wanted
}

async function gh(argv, input) {
  const result = await run('gh', argv, { input, timeout: 60_000 })
  if (result.code !== 0) throw Error(`gh ${argv.slice(0, 2).join(' ')} failed: ${result.stderr.trim()}`)
  return result.stdout
}

const marker = item => `<!-- ${item.fingerprint} -->`

function body(item) {
  return [
    marker(item),
    `**Area:** ${item.area} · **Severity:** ${item.severity}`,
    '',
    '### Evidence',
    item.evidence ? '```\n' + String(item.evidence).slice(0, 6000) + '\n```' : '_none_',
    '',
    '### Suggestion',
    item.suggestion || '_none_',
    '',
    '_Opened by the Patronus QA routine (`qa/`). It comments here while the finding persists; close the issue once fixed._',
  ].join('\n')
}

/** Returns what was done per finding: created, commented or (dry run) planned. */
export async function upsert(findings, { dryRun = true } = {}) {
  const outcomes = []
  if (!dryRun) for (const [name, color] of Object.entries(labelsFor(findings))) await gh(['label', 'create', name, '--color', color, '--force'])
  for (const item of findings) {
    if (dryRun) { outcomes.push({ fingerprint: item.fingerprint, action: 'planned', title: item.title }); continue }
    const found = JSON.parse(await gh(['issue', 'list', '--label', 'qa', '--state', 'open', '--search', `"${item.fingerprint}" in:body`, '--json', 'number,body', '--limit', '5']))
    const existing = found.find(issue => issue.body.includes(marker(item)))
    if (existing) {
      const note = `Still present on ${new Date().toISOString().slice(0, 10)}.` + (item.metric ? ` Current value: \`${JSON.stringify(item.metric)}\`.` : '') +
        (item.instances ? '\n\n' + item.instances.map(title => `- ${title}`).join('\n') : '')
      await gh(['issue', 'comment', String(existing.number), '--body-file', '-'], note)
      outcomes.push({ fingerprint: item.fingerprint, action: 'commented', issue: existing.number })
    } else {
      const url = (await gh(['issue', 'create', '--title', `[QA] ${item.title}`, '--label', 'qa', '--label', `qa/${item.area}`, '--body-file', '-'], body(item))).trim()
      outcomes.push({ fingerprint: item.fingerprint, action: 'created', url })
    }
  }
  return outcomes
}

const mostSevere = items => items.reduce((worst, item) => severities.indexOf(item.severity) < severities.indexOf(worst) ? item.severity : worst, 'low')

/** One finding per group: the issue keeps its fingerprint whichever hosts or steps show the problem today. */
function merge(group, items) {
  return {
    area: items[0].area, severity: mostSevere(items), fingerprint: group.fingerprint, title: group.title,
    evidence: items.map(item => `${item.title}\n${item.evidence || JSON.stringify(item.metric ?? null)}`).join('\n\n'),
    suggestion: items.find(item => item.suggestion)?.suggestion ?? '', instances: items.map(item => item.title),
  }
}

/** Collects every area report of a run directory, deduplicated by fingerprint and merged by group, most severe first. */
export async function collect(directory) {
  const seen = new Map()
  for (const name of (await readdir(directory)).filter(name => name.endsWith('.json') && name !== 'issues.json')) {
    const value = JSON.parse(await readFile(join(directory, name), 'utf8'))
    for (const item of value.findings ?? []) if (!seen.has(item.fingerprint)) seen.set(item.fingerprint, item)
  }
  const groups = new Map(), single = []
  for (const item of seen.values()) {
    if (!item.group) { single.push(item); continue }
    if (!groups.has(item.group.fingerprint)) groups.set(item.group.fingerprint, { group: item.group, items: [] })
    groups.get(item.group.fingerprint).items.push(item)
  }
  return [...single, ...[...groups.values()].map(({ group, items }) => merge(group, items))]
    .sort((a, b) => severities.indexOf(a.severity) - severities.indexOf(b.severity))
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const options = args()
  const directory = options.out ?? join(qaHome, 'runs', new Date().toISOString().slice(0, 10))
  const outcomes = await upsert(await collect(directory), options)
  for (const outcome of outcomes) process.stdout.write(`${outcome.action}: ${outcome.title ?? outcome.url ?? '#' + outcome.issue}\n`)
  if (options.dryRun) process.stdout.write('Dry run: pass --publish to create or comment on GitHub issues.\n')
}
