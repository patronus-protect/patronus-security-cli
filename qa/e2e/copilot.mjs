// GitHub Copilot CLI sessions for the e2e QA: the real `copilot` binary in prompt mode (`-p`) with an
// isolated COPILOT_HOME, offline BYOK mode (COPILOT_OFFLINE=true) and a scripted OpenAI-compatible
// chat-completions endpoint, so no GitHub login is used. The Patronus plugin loads through
// `--plugin-dir plugins/copilot` (its hooks/hooks.json and .mcp.json); the tracker MCP server through
// `--additional-mcp-config`. In prompt mode Copilot denies every hook `ask` ("unable to ask user"),
// so risky shell commands and PII disclosure are denied rather than approved.
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { repository } from '../lib/common.mjs'
import { trackerServer } from './scenario.mjs'

export const pluginRoot = join(repository, 'plugins/copilot')

/** OpenAI chat-completions endpoint; `state.respond(body)` returns a tool call, text or nothing. */
async function chatServer(state) {
  const server = createServer(async (request, response) => {
    let text = ''
    for await (const part of request) text += part
    const body = text ? JSON.parse(text) : {}
    if (!request.url.includes('/chat/completions')) {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify({ object: 'list', data: [{ id: 'scripted', object: 'model' }] }))
      return
    }
    const main = Array.isArray(body.tools) && body.tools.length > 0
    const reply = main ? state.respond(body) : { content: 'ok' }
    const message = reply.call
      ? { role: 'assistant', content: null, tool_calls: [{ id: reply.call.id, type: 'function', function: { name: reply.call.name, arguments: JSON.stringify(reply.call.args) } }] }
      : { role: 'assistant', content: reply.content ?? 'done' }
    const finish = reply.call ? 'tool_calls' : 'stop'
    const usage = { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 }
    if (!body.stream) {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify({ id: 'qa', object: 'chat.completion', created: 1, model: 'scripted', choices: [{ index: 0, message, finish_reason: finish }], usage }))
      return
    }
    response.writeHead(200, { 'content-type': 'text/event-stream' })
    const delta = reply.call ? { role: 'assistant', tool_calls: [{ index: 0, ...message.tool_calls[0] }] } : { role: 'assistant', content: message.content }
    const chunk = (choice, extra = {}) => response.write(`data: ${JSON.stringify({ id: 'qa', object: 'chat.completion.chunk', created: 1, model: 'scripted', choices: [choice], ...extra })}\n\n`)
    chunk({ index: 0, delta, finish_reason: null })
    chunk({ index: 0, delta: {}, finish_reason: finish }, { usage })
    response.end('data: [DONE]\n\n')
  })
  await new Promise((ok, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', ok) })
  return { url: `http://127.0.0.1:${server.address().port}/v1`, close: () => new Promise(ok => { server.closeAllConnections(); server.close(ok) }) }
}

/** The tool outputs of the newest request: tool messages after the last assistant message. */
function toolOutputs(messages) {
  const outputs = new Map()
  for (let at = messages.length - 1; at >= 0 && messages[at].role === 'tool'; at--) {
    const content = messages[at].content
    outputs.set(messages[at].tool_call_id, typeof content === 'string' ? content : JSON.stringify(content))
  }
  return outputs
}

const lastUser = messages => {
  const message = [...messages].reverse().find(item => item.role === 'user')
  return typeof message?.content === 'string' ? message.content : JSON.stringify(message?.content ?? '')
}

/** Isolated Copilot home; `plugin` loads the Patronus plugin. */
export async function copilotSession({ root, cwd, env, plugin, binary }) {
  const state = { requests: [], model: undefined, respond: () => ({ content: 'done' }) }
  const sessionId = randomUUID()
  const server = await chatServer(state)
  const home = join(root, 'home')
  await mkdir(join(home, '.copilot'), { recursive: true })
  const mcpConfig = join(root, 'tracker-mcp.json')
  await writeFile(mcpConfig, JSON.stringify({ mcpServers: { tracker: { type: 'stdio', command: process.execPath, args: [trackerServer], tools: ['*'] } } }))
  const hostEnv = {
    ...env, HOME: home, COPILOT_HOME: join(home, '.copilot'), COPILOT_OFFLINE: 'true', COPILOT_PROVIDER_BASE_URL: server.url,
    COPILOT_MODEL: 'gpt-4.1', COPILOT_AUTO_UPDATE: 'false', NO_COLOR: '1',
  }

  function launch(prompt, sessionId, timeout = 600_000) {
    const argv = ['-p', prompt, '--allow-all-tools', '--session-id', sessionId, '--additional-mcp-config', `@${mcpConfig}`,
      '--log-dir', join(root, 'logs'), '--disable-builtin-mcps', ...(plugin ? ['--plugin-dir', pluginRoot] : [])]
    return new Promise(resolve => {
      const started = Date.now()
      const child = spawn(binary, argv, { cwd, env: hostEnv, stdio: ['ignore', 'pipe', 'pipe'] })
      let stdout = '', stderr = ''
      child.stdout.on('data', chunk => { stdout += chunk })
      child.stderr.on('data', chunk => { stderr += chunk })
      const timer = setTimeout(() => child.kill('SIGKILL'), timeout)
      child.on('close', code => { clearTimeout(timer); resolve({ code: code ?? -1, ms: Date.now() - started, stdout, stderr }) })
    })
  }

  return {
    requests: state.requests,
    /** Drives the scripted model through the plan in one prompt-mode session. */
    async work(model, task) {
      state.respond = body => {
        const entry = { text: JSON.stringify(body.messages ?? []), at: Date.now(), main: true, step: Math.max(0, model.index) }
        state.requests.push(entry)
        const action = model.next(toolOutputs(body.messages ?? []), entry.at)
        if (action.type === 'done') return { content: 'done' }
        if (action.type === 'patronus') return { call: { id: action.id, name: `patronus-${action.op}`, args: action.args } }
        const step = action.step
        const call = (name, args) => ({ call: { id: action.id, name, args } })
        if (step.tool === 'read') return call('view', { path: join(cwd, step.path) })
        if (step.tool === 'shell') return call('bash', { command: step.cmd, description: step.id })
        if (step.tool === 'grep') return call('grep', { pattern: step.pattern, paths: join(cwd, 'data'), glob: 'customers.csv', output_mode: 'content', '-n': true })
        if (step.tool === 'mcp') return call('tracker-get_issue', { id: step.issue })
        throw Error(`Unknown tool ${step.tool}`)
      }
      const result = await launch(task, sessionId)
      return { ...result, stderr: result.stderr.slice(-2000) }
    },
    /** Prompt-gate phases, all in this object's one chat; the scripted model relays what it received, as instructed. */
    async gate(phases) {
      const out = []
      state.respond = body => {
        const received = lastUser(body.messages ?? [])
        state.requests.push({ text: received, at: Date.now(), main: true, step: 0 })
        return { content: received }
      }
      for (const prompt of phases) {
        const before = state.requests.length
        const result = await launch(prompt, sessionId, 180_000)
        out.push({ ...result, received: state.requests.slice(before).map(request => request.text) })
      }
      return out
    },
    close: () => server.close(),
  }
}
