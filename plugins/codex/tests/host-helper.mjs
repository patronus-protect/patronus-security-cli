import { createServer } from 'node:http'
import { spawn } from 'node:child_process'
import { appendFile, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline'

export const quote = value => `'${value.replaceAll("'", "'\\''")}'`

export async function run(command, args, options) {
  const child = spawn(command, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] })
  const output = { stdout: '', stderr: '' }
  for (const key of ['stdout', 'stderr']) child[key].on('data', data => { output[key] += data })
  const timer = setTimeout(() => child.kill('SIGKILL'), 60_000)
  try {
    const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve) })
    return { code, ...output }
  } finally { clearTimeout(timer) }
}

/** Trust only this test's generated hook definitions through Codex's own hashes. */
export async function trustHooks(binary, cwd, env, persist = true) {
  const child = spawn(binary, ['app-server'], { cwd, env, stdio: ['pipe', 'pipe', 'pipe'] })
  const pending = new Map()
  let id = 0
  let stderr = ''
  child.stderr.on('data', data => { stderr += data })
  const lines = createInterface({ input: child.stdout })
  lines.on('line', line => {
    try {
      const response = JSON.parse(line)
      const waiter = pending.get(response.id)
      if (!waiter) return
      pending.delete(response.id)
      response.error ? waiter.reject(new Error(JSON.stringify(response.error))) : waiter.resolve(response.result)
    } catch {}
  })
  const rpc = (method, params) => new Promise((resolve, reject) => {
    const key = ++id
    pending.set(key, { resolve, reject })
    child.stdin.write(JSON.stringify({ id: key, method, params }) + '\n')
  })
  const timer = setTimeout(() => {
    for (const waiter of pending.values()) waiter.reject(new Error('Codex hook metadata timed out: ' + stderr))
    child.kill('SIGKILL')
  }, 20_000)
  try {
    await rpc('initialize', { clientInfo: { name: 'patronus-hook-test', version: '0.1.0' }, capabilities: { experimentalApi: true } })
    child.stdin.write(JSON.stringify({ method: 'initialized' }) + '\n')
    const result = await rpc('hooks/list', { cwds: [cwd] })
    const hooks = result.data.flatMap(entry => entry.hooks)
    if (!hooks.length) throw new Error('No test hooks discovered: ' + JSON.stringify(result))
    const settings = hooks.map(hook => `\n[hooks.state.${JSON.stringify(hook.key)}]\nenabled = true\ntrusted_hash = ${JSON.stringify(hook.currentHash)}\n`).join('')
    if (persist) await appendFile(join(env.CODEX_HOME, 'config.toml'), settings)
    else if (hooks.some(hook => !hook.enabled || hook.trustStatus !== 'trusted')) throw Error('Installed hooks are not trusted')
    return hooks.map(({ key, eventName, currentHash }) => ({ key, eventName, currentHash }))
  } finally {
    clearTimeout(timer)
    child.stdin.end()
    child.kill('SIGTERM')
    lines.close()
  }
}

export async function scriptedServer(next) {
  const requests = []
  const errors = []
  const server = createServer(async (req, res) => {
    const chunks = []
    for await (const chunk of req) chunks.push(chunk)
    if (!req.url?.endsWith('/responses')) { res.writeHead(404); res.end(); return }
    const body = JSON.parse(Buffer.concat(chunks).toString())
    requests.push(body)
    let output
    try { output = await next(body, requests.length) }
    catch (error) { errors.push(error); output = [done()] }
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'close' })
    const emit = (type, fields) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...fields })}\n\n`)
    const response = { id: 'resp-' + requests.length, object: 'response', created_at: 1, model: 'patronus-test', status: 'in_progress', output: [] }
    emit('response.created', { response })
    output.forEach((item, index) => {
      emit('response.output_item.added', { output_index: index, item })
      if (item.type === 'message') emit('response.output_text.delta', { item_id: item.id, output_index: index, content_index: 0, delta: item.content[0].text })
      emit('response.output_item.done', { output_index: index, item })
    })
    emit('response.completed', { response: { ...response, status: 'completed', output, usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } })
    res.end()
  })
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
  return { requests, errors, url: `http://127.0.0.1:${server.address().port}/v1`, close: () => new Promise(resolve => server.close(resolve)) }
}

export const call = (name, args, id = 'call-fixture') => ({ type: 'function_call', id: 'fc-' + id, call_id: id, name, arguments: JSON.stringify(args), status: 'completed' })
export const done = () => ({ type: 'message', id: 'msg-done', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'Fixture complete.', annotations: [] }] })

export async function homeConfig(root, url) {
  const home = join(root, 'codex-home')
  const dataRoot = await mkdtemp(join(process.platform === 'darwin' ? '/private/tmp' : tmpdir(), 'patronus-codex-data-'))
  await mkdir(home, { recursive: true })
  await writeFile(join(home, 'config.toml'), `model = "patronus-test"\nmodel_provider = "patronus_test"\nmodel_reasoning_effort = "low"\nchatgpt_base_url = ${JSON.stringify(url)}\n[model_providers.patronus_test]\nname = "Local scripted fixture"\nbase_url = ${JSON.stringify(url)}\nwire_api = "responses"\nrequires_openai_auth = false\nrequest_max_retries = 0\nstream_max_retries = 0\n`)
  // An isolated child Codex installation; the calling task's home/config is untouched.
  const env = {
    ...process.env,
    HOME: root,
    XDG_CONFIG_HOME: join(root, 'xdg-config'),
    XDG_DATA_HOME: join(root, 'xdg-data'),
    CODEX_HOME: home,
    PATRONUS_DATA_DIR: dataRoot,
    CODEX_OTEL_DISABLE: '1',
  }
  for (const key of ['OPENAI_API_KEY', 'CODEX_API_KEY', 'ANTHROPIC_API_KEY']) delete env[key]
  return env
}
