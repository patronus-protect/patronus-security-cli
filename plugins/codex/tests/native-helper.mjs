import assert from 'node:assert/strict'
import { appendFile, cp, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { run, homeConfig, scriptedServer, trustHooks, call } from './host-helper.mjs'

export const binary = process.env.PATRONUS_CODEX_BIN
export const scanner = process.env.PATRONUS_SCANNER_BIN
if (!binary || !scanner) throw Error('Set PATRONUS_CODEX_BIN and PATRONUS_SCANNER_BIN to trusted installed CLIs.')
const plugin = process.env.PATRONUS_CODEX_PLUGIN_ROOT || fileURLToPath(new URL('..', import.meta.url))
let versions

/** Installs the actual bundle; no hook trust bypass and no user's Codex home. */
export async function nativeFixture(next, overrides = {}, options = {}) {
  versions ??= Promise.all([run(binary, ['--version'], {}), run(scanner, ['version'], {})]).then(([host, ark]) => {
    assert.equal(host.code, 0)
    assert.equal(ark.code, 0)
    assert.match(host.stdout, /^codex-cli \d+\.\d+\.\d+\s*$/)
    if (process.env.PATRONUS_CODEX_EXPECTED_VERSION) assert.equal(host.stdout.trim(), `codex-cli ${process.env.PATRONUS_CODEX_EXPECTED_VERSION}`)
    assert(ark.stdout.includes('patronus-ark 0.1.7'))
  })
  await versions
  const root = await mkdtemp(join(options.tempRoot ?? tmpdir(), 'patronus-codex-native-'))
  const cwd = join(root, 'workspace')
  await mkdir(cwd)
  const server = await scriptedServer(next)
  const env = await homeConfig(root, server.url)
  const config = join(root, 'scanner.toml')
  await writeFile(config, '[provider]\nmode = "local"\n[ark]\ncategories = ["prompt_injection"]\nmax_level = "l1"\ndownload_files = false\n')
  Object.assign(env, { PATRONUS_SCANNER_BIN: scanner, PATRONUS_CONFIG: config,
    PATRONUS_NATIVE_STATE_DIR: join(root, 'native-state'), PATRONUS_RESPONSE_WAIT_MS: '0' }, overrides)
  if (options.codeMode) await appendFile(join(env.CODEX_HOME, 'config.toml'), '\n[features]\ncode_mode = true\n' + (options.subagents ? 'multi_agent = true\n' : ''))
  if (options.mixedMcp) {
    const mixed = join(root, 'mixed-mcp.mjs')
    const image = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGOoCNAAAAI0APHlrLKsAAAAAElFTkSuQmCC'
    await writeFile(mixed, `import readline from 'node:readline';const reply=(id,result)=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',id,result})+'\\n');readline.createInterface({input:process.stdin}).on('line',line=>{const r=JSON.parse(line);if(r.id===undefined)return;if(r.method==='initialize')reply(r.id,{protocolVersion:'2025-06-18',capabilities:{tools:{}},serverInfo:{name:'mixed',version:'1'}});else if(r.method==='tools/list')reply(r.id,{tools:[{name:'mixed_content',description:'Return deterministic mixed test content.',inputSchema:{type:'object',properties:{topic:{type:'string'}},required:['topic'],additionalProperties:false},annotations:{readOnlyHint:true}}]});else if(r.method==='tools/call')reply(r.id,{content:[{type:'text',text:'MCP_TEXT_SAFE731'},{type:'image',data:${JSON.stringify(image)},mimeType:'image/png'}],structuredContent:{private:'MCP_STRUCTURED_PRIVATE731'}});else reply(r.id,{});});`)
    await appendFile(join(env.CODEX_HOME, 'config.toml'), `\n[mcp_servers.mixed]\ncommand = ${JSON.stringify(process.execPath)}\nargs = [${JSON.stringify(mixed)}]\nstartup_timeout_sec = 10\ntool_timeout_sec = 20\n`)
  }
  const marketplaceName = options.marketplaceName ?? 'patronus-native-test'
  const market = join(root, 'marketplace')
  const destination = join(market, 'plugins/patronus-security')
  await mkdir(join(market, '.agents/plugins'), { recursive: true })
  await mkdir(destination, { recursive: true })
  if (options.lifecycle) await cp(plugin, destination, { recursive: true })
  else for (const entry of ['.codex-plugin', '.mcp.json', 'hooks', 'scripts', 'skills']) {
    await cp(join(plugin, entry), join(destination, entry), { recursive: true })
  }
  await writeFile(join(market, '.agents/plugins/marketplace.json'), JSON.stringify({ name: marketplaceName,
    interface: { displayName: 'Isolated native test' }, plugins: [{ name: 'patronus-security',
      source: { source: 'local', path: './plugins/patronus-security' },
      policy: { installation: 'AVAILABLE', authentication: 'ON_INSTALL' }, category: 'Developer Tools' }] }))
  if (options.preparePlugin) await options.preparePlugin(destination)
  let hookCapture
  if (options.captureHooks) {
    hookCapture = join(root, 'captured-hooks.jsonl')
    const capture = join(root, 'capture-hook.mjs')
    await writeFile(capture, `import fs from 'node:fs';let data='';for await(const chunk of process.stdin)data+=chunk;fs.appendFileSync(${JSON.stringify(hookCapture)},data.trim()+'\\n');const value=JSON.parse(data);let result={};if(value.tool_name==='view_image'){if(value.hook_event_name==='PreToolUse')result={hookSpecificOutput:{hookEventName:'PreToolUse',permissionDecision:'deny',permissionDecisionReason:'VIEW_IMAGE_BLOCKED_BY_TEST'}};if(value.hook_event_name==='PermissionRequest')result={hookSpecificOutput:{hookEventName:'PermissionRequest',decision:{behavior:'deny',message:'VIEW_IMAGE_BLOCKED_BY_TEST'}}};if(value.hook_event_name==='PostToolUse')result={decision:'block',reason:'VIEW_IMAGE_BLOCKED_BY_TEST'};}process.stdout.write(JSON.stringify(result));`)
    const command = `${process.execPath} ${capture}`
    const toolHook = [{ matcher: '.*', hooks: [{ type: 'command', command, timeout: 10 }] }]
    const lifecycleHook = [{ hooks: [{ type: 'command', command, timeout: 10 }] }]
    await writeFile(join(env.CODEX_HOME, 'hooks.json'), JSON.stringify({ hooks: {
      PreToolUse: toolHook,
      PermissionRequest: toolHook,
      PostToolUse: toolHook,
      UserPromptSubmit: lifecycleHook,
      SessionStart: lifecycleHook,
      Stop: lifecycleHook,
    } }))
  }
  try {
    for (const args of [['plugin', 'marketplace', 'add', market], ['plugin', 'add', `patronus-security@${marketplaceName}`]]) {
      const result = await run(binary, args, { cwd, env })
      assert.equal(result.code, 0, JSON.stringify(result))
    }
    if (options.lifecycle) {
      if (options.captureHooks) await trustHooks(binary, cwd, env)
      const enabled = await run(scanner, ['integration', 'codex', 'enable'], { cwd, env: { ...env, PATRONUS_CODEX_BIN: binary } })
      assert.equal(enabled.code, 0, enabled.stderr)
    }
    const trusted = await trustHooks(binary, cwd, env, !options.lifecycle)
    const events = new Set(trusted.map(hook => hook.eventName))
    for (const event of ['preToolUse', 'postToolUse', 'userPromptSubmit', 'sessionStart', 'stop']) {
      assert(events.has(event), `Missing required hook event ${event}: ${JSON.stringify(trusted)}`)
    }
    return { root, cwd, env, server, trusted, hookCapture, market, destination,
      async exec(label = 'fixture', options = {}) {
        const { expectSuccess = true, bypassApprovals = false, ephemeral = true, prompt = 'Perform the local fixture task.' } = options
        const isolation = bypassApprovals ? ['--dangerously-bypass-approvals-and-sandbox'] : ['--sandbox', 'workspace-write']
        const result = await run(binary, ['exec', ...(ephemeral ? ['--ephemeral'] : []), '--skip-git-repo-check', '--json', ...isolation, '-C', cwd, prompt], { cwd, env })
        await writeFile(join(root, `${label}-host.json`), JSON.stringify(result))
        await writeFile(join(root, `${label}-requests.json`), JSON.stringify(server.requests))
        assert.equal(server.errors.length, 0, 'Scripted model assertion failed; inspect ' + root + ': ' + server.errors.map(error => error.stack).join('\n'))
        if (expectSuccess) assert.equal(result.code, 0, 'Codex failed; inspect ' + root + ': ' + result.stderr.slice(-1500))
        return result
      },
      async close() { await server.close() },
    }
  } catch (error) { await server.close(); throw error }
}

/** Native denial feedback embeds the receipt inside the tool-output string. */
export function lastReceipt(body) {
  const receipts = []
  const visit = value => {
    if (typeof value === 'string') {
      const start = value.indexOf('{'), end = value.lastIndexOf('}')
      if (start >= 0 && end > start) { try { visit(JSON.parse(value.slice(start, end + 1))) } catch {} }
    } else if (value && typeof value === 'object') {
      if (typeof value.status === 'string' && (typeof value.scan_id === 'string' || typeof value.approved === 'boolean')) receipts.push(value)
      for (const child of Object.values(value)) visit(child)
    }
  }
  for (const item of body.input ?? []) if (['function_call_output', 'custom_tool_call_output'].includes(item.type)) visit(item.output)
  assert(receipts.length > 0, 'No receipt in model request: ' + JSON.stringify(body.input))
  return receipts.at(-1)
}

export async function readCounter(path) { try { return await readFile(path, 'utf8') } catch (error) { if (error.code === 'ENOENT') return ''; throw error } }

export function patronusCall(body, tool, args, id) {
  const group = body.tools.find(item => item.type === 'namespace' && item.name === 'mcp__patronus__')
  if (group) {
    assert(group.tools.some(item => item.name === tool), 'Missing installed Patronus tool: ' + tool)
    return { ...call(tool, args, id), namespace: group.name }
  }
  const name = 'mcp__patronus__' + tool
  assert(body.tools.some(item => item.name === name), 'Missing installed Patronus tool: ' + name)
  return call(name, args, id)
}

export function namespaceCall(body, namespace, tool, input, id) {
  const group = body.tools.find(item => item.type === 'namespace' && item.name === namespace)
  if (!group) return undefined
  const definition = group.tools.find(item => item.name === tool)
  assert(definition, 'Missing namespaced tool: ' + namespace + '.' + tool)
  if (definition.type === 'custom') return { type: 'custom_tool_call', id: 'ct-' + id, call_id: id, name: tool, namespace, input, status: 'completed' }
  return { ...call(tool, input, id), namespace }
}

export function customCall(body, tool, input, id) {
  const definition = body.tools.find(item => item.type === 'custom' && item.name === tool)
  if (!definition) return undefined
  return { type: 'custom_tool_call', id: 'ct-' + id, call_id: id, name: tool, input, status: 'completed' }
}
