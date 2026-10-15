// Sandbox helpers shared by the hook and e2e QA: global-config guard, hook journal, stray cleanup.
import { existsSync } from 'node:fs'
import { readFile, readdir } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { percentile, rate, run, scanner, sha256 } from './common.mjs'

export const hosts = ['claude', 'codex', 'cursor']
export const bin = name => [join(homedir(), '.local/bin', name), `/opt/homebrew/bin/${name}`, `/usr/local/bin/${name}`].find(existsSync) ?? name
export const hostPath = () => `${join(homedir(), '.local/bin')}:${process.env.PATH}`

const globalFiles = [
  '.claude/settings.json', '.claude/plugins/installed_plugins.json', '.claude/plugins/known_marketplaces.json',
  '.codex/config.toml', '.codex/hooks.json',
  '.cursor/hooks.json', '.cursor/mcp.json',
].map(path => join(homedir(), path))

/** Hashes of the global host config files plus each host's Patronus integration state. */
export async function snapshot() {
  const files = {}
  for (const path of globalFiles) files[path] = existsSync(path) ? sha256(await readFile(path)) : null
  const status = {}
  for (const host of hosts) {
    const result = await run(scanner, ['integration', host, 'status', '--format', 'json'], { timeout: 60_000, env: { ...process.env, PATH: hostPath() } })
    try { status[host] = JSON.parse(result.stdout).state ?? 'unknown' } catch { status[host] = 'unreadable' }
  }
  return { files, status }
}

export const changedFiles = (before, after) => Object.keys(before.files).filter(path => before.files[path] !== after.files[path])

/** Protocol journal events (hook_started/hook_completed, scans) of one data dir since a timestamp. */
export async function journal(dataDir, since = 0) {
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

export const sessionHash = (host, session) => `sha256:${sha256(JSON.stringify([host, session]))}`

/** Success, error, timeout and latency per host:hook_event from hook_started/hook_completed pairs. */
/** Tool results in shapes the hook mapper does not know were passed on unscanned. */
export const unscannedResults = stats => Object.values(stats).reduce((sum, stat) => sum + (stat.errors?.unscanned_shape ?? 0), 0)

export function hookMetrics(events) {
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

/** Kills processes (brokers, scanners, MCP servers) whose command line names a sandbox path. */
export async function killStrays(root) {
  const { stdout } = await run('ps', ['-axo', 'pid=,command='], { timeout: 10_000 })
  const pids = stdout.split('\n').filter(line => line.includes(root)).map(line => Number.parseInt(line, 10)).filter(pid => pid && pid !== process.pid)
  for (const pid of pids) try { process.kill(pid, 'SIGKILL') } catch {}
  return pids.length
}
