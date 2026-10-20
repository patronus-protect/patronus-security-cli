// Cursor e2e driver: an emulated Cursor agent loop around the real Patronus hook bundle.
//
// The public cursor-agent build runs every agent turn through Cursor's backend and needs a Cursor
// login, so a scripted model cannot drive the real binary (its `--base-url`/`--authless` local mode
// is not shipped). This driver reproduces what cursor-agent 2026.10.14 does around each tool, as
// read from its bundle (190.index.js, hook executor and tool executors):
//   - Read:  read the file, run `beforeReadFile` with {content, file_path}; `permission: deny` turns
//            the read into the error "File read was blocked by a hook: <user_message>".
//   - Shell: `beforeShellExecution` with {command, cwd, sandbox}; `deny` blocks ("Command execution was
//            blocked by a hook: <user_message>"), `ask` goes to the user (the scripted user approves);
//            then run the command and `postToolUse` with tool_output {output, exitCode} (JSON string);
//            only `additional_context` is honoured, appended after the output.
//   - MCP:   call the server, then `postToolUse` with tool_name `MCP:<tool>` and tool_output
//            {content, isError}; `updated_mcp_tool_output` replaces what the model sees.
//   - Grep and Fetch: hooks receive only metadata ({pattern, success}); the model sees raw output.
//   - Prompt: `beforeSubmitPrompt` with {prompt}; `continue: false` keeps it from the model.
// Hook commands run exactly as plugins/cursor/hooks/hooks.json declares them (shell, stdin JSON,
// CURSOR_PLUGIN_ROOT set). Results are labelled `emulated` in the report.
import { spawn } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { repository, run } from '../lib/common.mjs'
import { trackerServer } from './scenario.mjs'

export const pluginRoot = join(repository, 'plugins/cursor')
const hookConfig = JSON.parse(await readFile(join(pluginRoot, 'hooks/hooks.json'), 'utf8'))

/** One stdio MCP client per server, answering requests in order. */
function mcpClient(command, args, env) {
  const child = spawn(command, args, { env, stdio: ['pipe', 'pipe', 'ignore'] })
  const waiting = new Map()
  let buffer = '', id = 0
  child.stdout.on('data', chunk => {
    buffer += chunk
    let newline
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1)
      try { const message = JSON.parse(line); waiting.get(message.id)?.(message); waiting.delete(message.id) } catch {}
    }
  })
  const request = (method, params) => new Promise(done => {
    const at = ++id
    waiting.set(at, done)
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: at, method, params }) + '\n')
  })
  return {
    ready: request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'cursor-e2e', version: '1' } }),
    call: async (name, args) => (await request('tools/call', { name, arguments: args })).result ?? { content: [{ type: 'text', text: 'MCP error' }], isError: true },
    close: () => child.kill(),
  }
}

/** A Cursor-like session for one conversation in `cwd`; `plugin` loads the Patronus hooks. */
export function cursorSession({ cwd, env, plugin }) {
  const conversation = randomUUID()
  const requests = []
  const hookLog = []
  const approvals = []
  const hookEnv = { ...env, CURSOR_PLUGIN_ROOT: pluginRoot, CURSOR_PROJECT_DIR: cwd, CURSOR_VERSION: 'emulated-2026.10.14' }
  const tracker = mcpClient(process.execPath, [trackerServer], env)
  const patronus = mcpClient(process.execPath, [join(pluginRoot, 'scripts/patronus.mjs'), 'mcp'], hookEnv)
  const common = event => ({ conversation_id: conversation, generation_id: randomUUID(), model: 'scripted', session_id: conversation,
    hook_event_name: event, cursor_version: 'emulated-2026.10.14', workspace_roots: [cwd], user_email: null, transcript_path: null })

  /** Runs every configured command for an event and merges outputs like Cursor (last field wins). */
  async function hook(event, fields) {
    if (!plugin) return {}
    let merged = {}
    for (const entry of hookConfig.hooks[event] ?? []) {
      const input = JSON.stringify({ ...common(event), ...fields })
      const started = Date.now()
      const result = await run('/bin/sh', ['-c', entry.command], { cwd, env: hookEnv, input, timeout: (entry.timeout ?? 60) * 1000 })
      let output = {}
      // Exit 0 with JSON is honoured; anything else fails open, as Cursor does without failClosed.
      if (result.code === 0) try { output = JSON.parse(result.stdout.trim() || '{}') } catch { output = {} }
      hookLog.push({ event, ms: Date.now() - started, code: result.code })
      merged = { ...merged, ...output }
    }
    return merged
  }

  async function tool(step) {
    const tool_use_id = randomUUID()
    if (step.tool === 'read') {
      const file_path = join(cwd, step.path)
      const content = await readFile(file_path, 'utf8')
      const decision = await hook('beforeReadFile', { content, file_path, attachments: [], tool_use_id })
      await hook('postToolUse', { tool_name: 'Read', tool_input: { path: file_path }, tool_output: JSON.stringify({ file_path, content_length: content.length }), duration: 1, tool_use_id, cwd })
      return decision.permission === 'deny' ? `File read was blocked by a hook: ${decision.user_message ?? ''}` : content
    }
    if (step.tool === 'shell') {
      const gate = await hook('beforeShellExecution', { command: step.cmd, cwd, sandbox: false, tool_use_id })
      if (gate.permission === 'deny') return `Command execution was blocked by a hook: ${gate.user_message ?? ''}`
      if (gate.permission === 'ask') approvals.push({ step: step.id, message: gate.user_message ?? '' })
      const result = await run('/bin/sh', ['-c', step.cmd], { cwd, env: { PATH: env.PATH, HOME: cwd }, timeout: 120_000 })
      const output = result.stdout + result.stderr
      const decision = await hook('postToolUse', { tool_name: 'Shell', tool_input: { command: step.cmd, cwd }, tool_output: JSON.stringify({ output, exitCode: result.code }), duration: result.ms, tool_use_id, cwd })
      return decision.additional_context ? `${output}\n\n${decision.additional_context}` : output
    }
    if (step.tool === 'grep') {
      const result = await run('grep', ['-n', step.pattern, step.path], { cwd, timeout: 30_000 })
      await hook('postToolUse', { tool_name: 'Grep', tool_input: { pattern: step.pattern, path: step.path }, tool_output: JSON.stringify({ pattern: step.pattern, success: true }), duration: 1, tool_use_id, cwd })
      return result.stdout
    }
    if (step.tool === 'mcp') return mcp(tracker, 'get_issue', { id: step.issue }, tool_use_id)
    throw Error(`Unknown tool ${step.tool}`)
  }

  async function mcp(client, name, args, tool_use_id = randomUUID()) {
    await client.ready
    const result = await client.call(name, args)
    const content = (result.content ?? []).map(block => block.type === 'text' ? { type: 'text', text: block.text } : { type: 'unknown' })
    const decision = await hook('postToolUse', { tool_name: `MCP:${name}`, tool_input: args, tool_output: JSON.stringify({ content, isError: Boolean(result.isError) }), duration: 1, tool_use_id })
    const visible = decision.updated_mcp_tool_output?.content ?? content
    const text = visible.filter(block => block.type === 'text').map(block => block.text).join('\n')
    return decision.additional_context ? `${text}\n\n${decision.additional_context}` : text
  }

  return {
    requests, hookLog, approvals,
    /** Drives the scripted model through the plan; each model request carries the latest tool output. */
    async work(model, task) {
      const started = Date.now()
      const outputs = new Map()
      requests.push({ text: task, at: Date.now(), main: true, step: 0 })
      for (;;) {
        const action = model.next(outputs)
        outputs.clear()
        if (action.type === 'done') break
        const text = action.type === 'tool' ? await tool(action.step) : await mcp(patronus, action.op, action.args)
        outputs.set(action.id, text)
        requests.push({ text, at: Date.now(), main: true, step: Math.max(0, model.index) })
      }
      return { code: 0, ms: Date.now() - started }
    },
    /** One user prompt: returns whether it reached the model and what Cursor showed the user. */
    async prompt(text) {
      const decision = await hook('beforeSubmitPrompt', { prompt: text, attachments: [], composer_mode: 'agent' })
      const reached = decision.continue !== false
      if (reached) requests.push({ text, at: Date.now(), main: true, step: 0 })
      return { reached, notes: decision.user_message ?? '' }
    },
    async close() {
      await hook('stop', { status: 'completed', loop_count: 0 })
      tracker.close(); patronus.close()
    },
  }
}
