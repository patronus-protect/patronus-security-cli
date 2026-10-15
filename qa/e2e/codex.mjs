// Codex sessions for the e2e QA: a real marketplace install in an isolated CODEX_HOME, a scripted
// Responses API, and app-server turns so disclosure approvals can be answered like the UI does.
import { spawn } from 'node:child_process'
import { appendFile, mkdir, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { trackerServer } from './scenario.mjs'

// native-helper reads PATRONUS_CODEX_BIN and PATRONUS_SCANNER_BIN at import.
const helpers = async () => ({ ...await import('../../plugins/codex/tests/host-helper.mjs'), ...await import('../../plugins/codex/tests/native-helper.mjs') })

const tracker = `\n[mcp_servers.tracker]\ncommand = ${JSON.stringify(process.execPath)}\nargs = [${JSON.stringify(trackerServer)}]\nstartup_timeout_sec = 20\ntool_timeout_sec = 60\ndefault_tools_approval_mode = "approve"\n`

/** Responses API handler for the scenario; `state.model` is swapped per turn. */
function responder(h, state) {
  return body => {
    const entry = { text: JSON.stringify(body.input ?? []), at: Date.now(), main: Boolean(body.tools?.length), step: state.model ? Math.max(0, state.model.index) : 0 }
    state.requests.push(entry)
    if (!entry.main || !state.model) return [h.done()]
    const outputs = new Map()
    for (const item of body.input ?? []) if (['function_call_output', 'custom_tool_call_output'].includes(item.type))
      outputs.set(item.call_id, typeof item.output === 'string' ? item.output : JSON.stringify(item.output))
    const action = state.model.next(outputs, entry.at)
    if (action.type === 'done') return [h.done()]
    if (action.type === 'patronus') return [h.patronusCall(body, action.op, action.args, action.id)]
    const step = action.step
    if (step.tool === 'mcp') return [h.namespaceCall(body, 'mcp__tracker__', 'get_issue', { id: step.issue }, action.id)
      ?? h.namespaceCall(body, 'mcp__tracker', 'get_issue', { id: step.issue }, action.id) ?? h.call('mcp__tracker__get_issue', { id: step.issue }, action.id)]
    const cmd = step.tool === 'read' ? `cat ${step.path}` : step.tool === 'grep' ? `grep -n ${step.pattern} ${step.path}` : step.cmd
    return [h.call('exec_command', { cmd }, action.id)]
  }
}

/** Isolated Codex home with (plugin) or without (baseline) the installed Patronus plugin. */
export async function codexHome({ root, plugin, env }) {
  const h = await helpers()
  const state = { requests: [], model: undefined }
  await mkdir(root, { recursive: true })
  let fixture
  if (plugin) {
    fixture = await h.nativeFixture(responder(h, state), {}, { tempRoot: root })
    // nativeFixture's own data dir and zero response wait are replaced by the QA sandbox values.
    await rm(fixture.env.PATRONUS_DATA_DIR, { recursive: true, force: true })
    delete fixture.env.PATRONUS_RESPONSE_WAIT_MS
  } else {
    const server = await h.scriptedServer(responder(h, state))
    const home = join(root, 'baseline')
    await mkdir(join(home, 'workspace'), { recursive: true })
    const base = await h.homeConfig(home, server.url)
    await rm(base.PATRONUS_DATA_DIR, { recursive: true, force: true })
    fixture = { root: home, cwd: join(home, 'workspace'), env: base, server, close: () => server.close() }
  }
  for (const key of ['PATRONUS_DATA_DIR', 'PATRONUS_CONFIG']) delete fixture.env[key]
  Object.assign(fixture.env, env)
  await appendFile(join(fixture.env.CODEX_HOME, 'config.toml'), tracker)
  return { ...fixture, state }
}

/** A Codex app-server; approval requests are answered by `decide(method, params)`. */
export function appServer(binary, { cwd, env }, decide) {
  const child = spawn(binary, ['app-server'], { cwd, env, stdio: ['pipe', 'pipe', 'pipe'], detached: true })
  const pending = new Map(), asked = [], notes = []
  let id = 0, stderr = '', turnDone
  child.stderr.on('data', part => { stderr += part })
  const send = message => child.stdin.write(JSON.stringify(message) + '\n')
  createInterface({ input: child.stdout }).on('line', line => {
    let message
    try { message = JSON.parse(line) } catch { return }
    if (message.id !== undefined && message.method) { asked.push({ method: message.method, params: message.params }); send({ id: message.id, result: decide(message.method, message.params) }) }
    else if (message.id !== undefined) { const waiter = pending.get(message.id); pending.delete(message.id); message.error ? waiter?.reject(Error(JSON.stringify(message.error))) : waiter?.resolve(message.result) }
    else { notes.push(message); if (message.method === 'turn/completed') turnDone?.() }
  })
  const rpc = (method, params) => new Promise((resolve, reject) => { const key = ++id; pending.set(key, { resolve, reject }); send({ id: key, method, params }) })
  const ready = rpc('initialize', { clientInfo: { name: 'patronus-qa-e2e', version: '0.1.0' }, capabilities: { experimentalApi: true } }).then(() => send({ method: 'initialized' }))
  return {
    asked, notes, get stderr() { return stderr },
    async thread() {
      await ready
      return (await rpc('thread/start', { cwd, approvalPolicy: 'on-request', sandbox: 'danger-full-access', ephemeral: true })).thread.id
    },
    async turn(threadId, text, timeout = 900_000) {
      const from = notes.length, started = Date.now()
      const done = new Promise(resolve => { turnDone = resolve })
      let timedOut = false
      const timer = setTimeout(() => { timedOut = true; turnDone() }, timeout)
      await rpc('turn/start', { threadId, input: [{ type: 'text', text }] })
      await done
      clearTimeout(timer)
      return { notes: notes.slice(from), ms: Date.now() - started, timedOut }
    },
    close() { child.stdin.end(); try { process.kill(-child.pid, 'SIGKILL') } catch {} },
  }
}

/** Disclosure prompts consume `decisions` in order; everything else the host asks is accepted and logged. */
export function decider(decisions) {
  const log = { reveal: [], other: [] }
  const decide = (method, params) => {
    const reveal = method === 'mcpServer/elicitation/request' && JSON.stringify(params).includes('patronus_reveal_pii')
    if (method === 'mcpServer/elicitation/request') {
      const allow = reveal ? decisions[Math.min(log.reveal.length, decisions.length - 1)] === 'allow' : true
      ;(reveal ? log.reveal : log.other).push({ method, decision: allow ? 'allow' : 'deny' })
      return { action: allow ? 'accept' : 'decline', content: null }
    }
    log.other.push({ method, decision: 'allow' })
    return { decision: 'accept' }
  }
  return { decide, log }
}
