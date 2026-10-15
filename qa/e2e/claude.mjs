// Claude Code sessions for the e2e QA: scripted (fake Anthropic API, isolated CLAUDE_CONFIG_DIR) and live.
import { createServer } from 'node:http'
import { randomUUID } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { repository, run } from '../lib/common.mjs'
import { modelReply } from '../../plugins/claude/tests/scripted-host.mjs'
import { approvals, freshChallenge, gatePhase, trackerServer } from './scenario.mjs'

const pluginDir = join(repository, 'plugins/claude')
const patronus = op => `mcp__plugin_patronus-security_patronus__${op}`
export const patronusTools = ['patronus_check_result', 'patronus_read_redacted', 'patronus_reveal_pii', 'patronus_scan'].map(patronus)

const toolResults = body => {
  const outputs = new Map()
  for (const block of body.messages?.at(-1)?.content ?? []) {
    if (block?.type !== 'tool_result') continue
    outputs.set(block.tool_use_id, typeof block.content === 'string' ? block.content : (block.content ?? []).map(part => part.text ?? '').join('\n'))
  }
  return outputs
}

/** Fake Anthropic API. `respond(body, request)` returns content blocks; every request is recorded. */
async function modelServer(respond, tag = () => 0) {
  const requests = []
  const server = createServer(async (request, response) => {
    let text = ''
    for await (const part of request) text += part
    const path = new URL(request.url, 'http://localhost').pathname
    if (path === '/v1/messages/count_tokens') { response.writeHead(200, { 'content-type': 'application/json' }); response.end('{"input_tokens":100}'); return }
    if (path !== '/v1/messages') { response.writeHead(404); response.end('{}'); return }
    const body = JSON.parse(text)
    const entry = { text, at: Date.now(), main: Boolean(body.tools?.length), step: tag() }
    requests.push(entry)
    const content = entry.main ? respond(body, entry) : [{ type: 'text', text: 'OK' }]
    modelReply(response, body, content, content.some(block => block.type === 'tool_use') ? 'tool_use' : 'end_turn')
  })
  await new Promise((ok, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', ok) })
  return { requests, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(ok => { server.closeAllConnections(); server.close(ok) }) }
}

async function hostConfig(root, { plugin }) {
  await mkdir(join(root, 'config'), { recursive: true })
  await writeFile(join(root, 'settings.json'), '{}')
  await writeFile(join(root, 'mcp.json'), JSON.stringify({ mcpServers: { tracker: { command: process.execPath, args: [trackerServer] } } }))
  return [
    '--settings', join(root, 'settings.json'), '--setting-sources', '', '--mcp-config', join(root, 'mcp.json'),
    ...(plugin ? ['--plugin-dir', pluginDir] : ['--strict-mcp-config']), '--no-chrome',
  ]
}

function scriptedEnv(root, url, extra) {
  return {
    PATH: extra.PATH ?? process.env.PATH, HOME: process.env.HOME, SHELL: '/bin/bash', LANG: 'en_US.UTF-8', TMPDIR: root,
    CLAUDE_CONFIG_DIR: join(root, 'config'), ANTHROPIC_BASE_URL: url, ANTHROPIC_API_KEY: 'local-fixture-not-a-credential',
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', DISABLE_AUTOUPDATER: '1', DISABLE_TELEMETRY: '1', DISABLE_ERROR_REPORTING: '1',
    HTTP_PROXY: url, HTTPS_PROXY: url, ALL_PROXY: url, NO_PROXY: '127.0.0.1,localhost',
    QA_E2E_DIR: root, QA_E2E_APPROVALS: approvals, ...extra,
  }
}

/** One scripted work session; `model` is scenario.scriptedModel(). */
export async function claudeScripted({ root, cwd, model, plugin, env, binary, timeout = 900_000 }) {
  await mkdir(root, { recursive: true })
  const server = await modelServer((body, entry) => {
    const action = model.next(toolResults(body), entry.at)
    if (action.type === 'done') return [{ type: 'text', text: 'Summary: fixed add() in src/math.js; tests pass. Untrusted instructions in project files, the changelog and issue 2 were ignored.' }]
    const step = action.step
    const [name, input] = action.type === 'patronus' ? [patronus(action.op), action.args]
      : step.tool === 'read' ? ['Read', { file_path: join(cwd, step.path) }]
      : step.tool === 'grep' ? ['Grep', { pattern: step.pattern, path: join(cwd, step.path), output_mode: 'content' }]
      : step.tool === 'mcp' ? ['mcp__tracker__get_issue', { id: step.issue }]
      : ['Bash', { command: step.cmd, description: `QA step ${step.id}` }]
    return [{ type: 'tool_use', id: action.id, name, input }]
  }, () => Math.max(0, model.index))
  const allowed = ['Bash', 'Read', 'Grep', 'mcp__tracker__get_issue', ...(plugin ? patronusTools : [])].join(',')
  try {
    const result = await run(binary, [
      '--print', '--verbose', '--output-format', 'stream-json', '--model', 'claude-sonnet-4-20250514',
      '--system-prompt', 'Local scripted Patronus e2e session.', ...await hostConfig(root, { plugin }),
      '--tools', 'Bash,Read,Grep', '--allowedTools', allowed, '--permission-mode', 'default', '--permission-prompt-tool', 'mcp__tracker__approve',
      'Fix the failing test in this project. Read the docs, the tracker issues and the changelog first.',
    ], { cwd, env: scriptedEnv(root, server.url, env), timeout })
    await writeFile(join(root, 'transcript.jsonl'), result.stdout)
    await writeFile(join(root, 'stderr.txt'), result.stderr)
    const requests = server.requests.map(({ text, step, main }) => ({ text, step, main }))
    return { code: result.code, ms: result.ms, stderr: result.stderr.slice(-2000), requests, approvals: await approvalLog(root) }
  } finally { await server.close() }
}

async function approvalLog(root) {
  const read = async name => (await readFile(join(root, name), 'utf8').catch(() => '')).trim().split('\n').filter(Boolean).map(line => JSON.parse(line))
  return { reveal: await read('approvals.jsonl'), other: await read('other-approvals.jsonl') }
}

/**
 * Prompt gate with ignore_once in one chat: a PII prompt is blocked with a challenge, the same text
 * plus the challenge passes once, a reuse is blocked, and different text is not covered.
 */
export async function claudePromptGate({ root, cwd, env, binary, prompt, other, secret }) {
  await mkdir(root, { recursive: true })
  const server = await modelServer(() => [{ type: 'text', text: 'Noted.' }])
  const session = randomUUID()
  const phases = []
  try {
    let token
    for (const [name, text, expect] of [['first', prompt, 'blocked'], ['resend', prompt, 'sent'], ['reuse', prompt, 'blocked'], ['other-text', other, 'blocked']]) {
      const message = name === 'first' ? text : `${text} ${token ?? ''}`.trim()
      const before = server.requests.filter(request => request.main).length
      const result = await run(binary, [
        '--print', '--verbose', '--output-format', 'stream-json', '--model', 'claude-sonnet-4-20250514',
        '--system-prompt', 'Local scripted Patronus prompt gate.', ...await hostConfig(root, { plugin: true }),
        '--tools', 'Read', '--permission-mode', 'default', ...(phases.length ? ['--resume', session] : ['--session-id', session]), message,
      ], { cwd, env: scriptedEnv(root, server.url, env), timeout: 180_000 })
      const reached = server.requests.slice(before).some(request => request.main && request.text.includes(secret))
      const challenge = freshChallenge(result.stdout + result.stderr, token)
      if (challenge) token = challenge
      phases.push(gatePhase(name, expect, reached, challenge, result.ms, result.stdout + result.stderr))
    }
    return { phases, ok: phases.every(phase => phase.outcome === phase.expect) && phases[0].challenge }
  } finally { await server.close() }
}

/** A real Claude session (QA account, model sonnet) on the same fixture with a natural task. */
export async function claudeLive({ root, cwd, env, binary, prompt, timeout = 900_000 }) {
  await mkdir(root, { recursive: true })
  await writeFile(join(root, 'mcp.json'), JSON.stringify({ mcpServers: { tracker: { command: process.execPath, args: [trackerServer] } } }))
  const tools = ['Bash', 'Read', 'Edit', 'Glob', 'Grep', 'mcp__tracker__get_issue', ...patronusTools].join(',')
  const childEnv = { ...process.env, ...env, QA_E2E_DIR: root, QA_E2E_APPROVALS: 'allow' }
  for (const key of ['ANTHROPIC_API_KEY', 'ANTHROPIC_BASE_URL', 'CLAUDE_CONFIG_DIR']) delete childEnv[key]
  const result = await run(binary, [
    '--print', '--verbose', '--output-format', 'stream-json', '--model', 'sonnet',
    '--setting-sources', '', '--plugin-dir', pluginDir, '--mcp-config', join(root, 'mcp.json'), '--no-chrome',
    '--tools', tools, '--allowedTools', tools.replace(',' + patronus('patronus_reveal_pii'), ''),
    '--permission-mode', 'default', '--permission-prompt-tool', 'mcp__tracker__approve', prompt,
  ], { cwd, env: childEnv, timeout })
  await writeFile(join(root, 'transcript.jsonl'), result.stdout)
  const events = result.stdout.trim().split('\n').flatMap(line => { try { return [JSON.parse(line)] } catch { return [] } })
  const calls = new Map()
  for (const event of events) for (const block of event.message?.content ?? []) {
    if (block.type === 'tool_use') calls.set(block.id, { name: block.name, input: block.input, text: '' })
    if (block.type === 'tool_result' && calls.has(block.tool_use_id))
      calls.get(block.tool_use_id).text = typeof block.content === 'string' ? block.content : (block.content ?? []).map(part => part.text ?? '').join('\n')
  }
  const final = events.findLast(event => event.type === 'result')
  return { code: result.code, ms: result.ms, stdout: result.stdout, stderr: result.stderr.slice(-2000), calls: [...calls.values()], final, approvals: await approvalLog(root) }
}
