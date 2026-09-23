import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, copyFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('./hook-fixture.mjs', import.meta.url));
const mcpFixture = fileURLToPath(new URL('./mcp-fixture.mjs', import.meta.url));
// Patronus answers its own tools from the plugin's MCP server. A user approves them
// once; the headless contract test pre-approves them as that user would.
const patronusTools = ['patronus_check_result', 'patronus_read_redacted', 'patronus_scan']
  .map(name => `mcp__plugin_patronus-security_patronus__${name}`);
const pluginRoot = process.env.PATRONUS_CLAUDE_PLUGIN_ROOT || fileURLToPath(new URL('../', import.meta.url));
const root = process.env.PATRONUS_CLAUDE_PROOF_ROOT ||
  (process.platform === 'darwin' ? '/private/tmp/patronus-claude-native-proof' : join(tmpdir(), 'patronus-claude-native-proof'));
const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;

function modelReply(response, body, content, stopReason) {
  const message = {
    id: 'msg_local_fixture', type: 'message', role: 'assistant',
    model: body.model, content, stop_reason: stopReason, stop_sequence: null,
    usage: { input_tokens: 100, output_tokens: 30 },
  };
  if (!body.stream) {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(message));
    return;
  }
  response.writeHead(200, { 'content-type': 'text/event-stream' });
  const event = (type, data) => response.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`);
  event('message_start', { message: { ...message, content: [], stop_reason: null } });
  for (const [index, block] of content.entries()) {
    event('content_block_start', {
      index, content_block: block.type === 'tool_use' ? { ...block, input: {} } : { type: 'text', text: '' },
    });
    event('content_block_delta', {
      index, delta: block.type === 'tool_use'
        ? { type: 'input_json_delta', partial_json: JSON.stringify(block.input) }
        : { type: 'text_delta', text: block.text },
    });
    event('content_block_stop', { index });
  }
  event('message_delta', { delta: { stop_reason: stopReason, stop_sequence: null }, usage: { output_tokens: 30 } });
  event('message_stop', {});
  response.end();
}

export async function runHost({ name, tool, input, policy = 'pass', batch = false, timeout = 30000, mcp = false, resume = false, postHookTimeout = 10, plugin = false, runtime = false, runtimeHookTimeout, flow, sourceText = 'RAW_RESPONSE_ONLY_SENTINEL\n', userPrompt = 'Perform the scripted local test.' }) {
  plugin ||= Boolean(runtime);
  await mkdir(root, { recursive: true });
  const directory = await mkdtemp(join(root, `${name}-`));
  await mkdir(join(directory, 'state'));
  const source = join(directory, 'source.txt');
  await writeFile(source, sourceText);
  await writeFile(join(directory, 'image.png'), Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jG2kAAAAASUVORK5CYII=', 'base64'));
  const actualInput = typeof input === 'function' ? input(directory, source) : input;
  const requests = [];
  const messages = [];
  const server = createServer(async (request, response) => {
    let text = '';
    for await (const part of request) text += part;
    const body = text ? JSON.parse(text) : {};
    const path = new URL(request.url, 'http://localhost').pathname;
    requests.push({ method: request.method, path, body }); // Never record auth headers.
    if (path === '/v1/messages/count_tokens') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{"input_tokens":100}');
    } else if (path === '/v1/messages') {
      messages.push(body);
      const first = messages.length === 1;
      const receiptId = flow === 'redacted' && messages.length === 2
        ? JSON.stringify(body.messages).match(/[a-f0-9]{32}/)?.[0] : undefined;
      const fileId = flow === 'static-redacted' && messages.length === 2
        ? JSON.stringify(body.messages).match(/file_[a-f0-9]{64}/)?.[0] : undefined;
      modelReply(response, body,
        first ? [{ type: 'tool_use', id: 'toolu_fixture', name: tool, input: actualInput }]
          : receiptId || fileId ? [{ type: 'tool_use', id: 'toolu_redacted',
            name: 'mcp__plugin_patronus-security_patronus__patronus_read_redacted', input: receiptId ? { scan_id: receiptId } : { file_id: fileId } }]
          : [{ type: 'text', text: 'LOCAL_TEST_COMPLETE' }],
        first || receiptId || fileId ? 'tool_use' : 'end_turn');
    } else {
      response.writeHead(404);
      response.end('{}');
    }
  });
  await new Promise((ok, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', ok); });
  server.unref();
  const baseURL = `http://127.0.0.1:${server.address().port}`;
  const command = `${quote(process.execPath)} --experimental-strip-types ${quote(fixture)}`;
  const hook = { type: 'command', command, timeout: 10 };
  const hooks = {
    UserPromptSubmit: [{ hooks: [hook] }],
    PreToolUse: [{ matcher: '*', hooks: [hook] }],
    PostToolUse: [{ matcher: '*', hooks: [{ ...hook, timeout: postHookTimeout }] }],
    PostToolUseFailure: [{ matcher: '*', hooks: [hook] }],
    ...(batch ? { PostToolBatch: [{ hooks: [hook] }] } : {}),
  };
  if (plugin) {
    // Exercise the shipped manifest/config discovery with a deterministic transport
    // stub. Shared broker/controller behavior is tested separately by its owner.
    for (const folder of ['.claude-plugin', 'hooks', 'scripts']) await mkdir(join(directory, 'plugin', folder), { recursive: true });
    for (const file of ['.claude-plugin/plugin.json', 'hooks/hooks.json', '.mcp.json']) {
      await copyFile(join(pluginRoot, file), join(directory, 'plugin', file));
    }
    if (runtimeHookTimeout !== undefined) {
      const path = join(directory, 'plugin/hooks/hooks.json');
      const config = JSON.parse(await readFile(path, 'utf8'));
      for (const hook of config.hooks.PostToolUse[0].hooks) hook.timeout = runtimeHookTimeout;
      await writeFile(path, JSON.stringify(config));
    }
    const launcher = runtime
      ? `import { spawnSync } from 'node:child_process';\nimport { readFileSync, appendFileSync } from 'node:fs';\n` +
        `const args = [${JSON.stringify(join(pluginRoot, 'scripts/patronus.mjs'))}, ...process.argv.slice(2)];\n` +
        `if (process.argv[2] === 'hook') {\n` +
        ` const input = readFileSync(0, 'utf8'); appendFileSync(process.env.PATRONUS_FIXTURE_DIRECTORY + '/hooks.jsonl', input.trim() + '\\n');\n` +
        ` const result = spawnSync(process.execPath, args, { input, encoding: 'utf8' });\n` +
        ` appendFileSync(process.env.PATRONUS_FIXTURE_DIRECTORY + '/hook-outputs.jsonl', JSON.stringify({event:process.argv[4],output:result.stdout}) + '\\n');\n` +
        ` process.stdout.write(result.stdout || ''); process.stderr.write(result.stderr || ''); process.exit(result.status ?? 1);\n` +
        `} else { const result = spawnSync(process.execPath, args, { stdio: 'inherit' }); process.exit(result.status ?? 1); }\n`
      : `import { spawnSync } from 'node:child_process';\n` +
        `const args = process.argv[2] === 'mcp' ? [${JSON.stringify(mcpFixture)}] : ['--experimental-strip-types', ${JSON.stringify(fixture)}];\n` +
        `const result = spawnSync(process.execPath, args, { stdio: 'inherit' });\nprocess.exit(result.status ?? 1);\n`;
    if (runtime?.direct) await copyFile(join(pluginRoot, 'scripts/patronus.mjs'), join(directory, 'plugin/scripts/patronus.mjs'));
    else await writeFile(join(directory, 'plugin/scripts/patronus.mjs'), launcher);
  }
  await writeFile(join(directory, 'settings.json'), JSON.stringify(plugin ? {} : { hooks }));
  await writeFile(join(directory, 'mcp.json'), JSON.stringify({ mcpServers: mcp && (!plugin || runtime) ? {
    [typeof mcp === 'string' ? mcp : 'fixture']: { command: process.execPath, args: [mcpFixture] },
  } : {} }));
  const env = {
    PATH: process.env.PATH, SHELL: process.env.SHELL || '/bin/sh', LANG: 'en_US.UTF-8',
    TMPDIR: directory, CLAUDE_CONFIG_DIR: join(directory, 'state'),
    ANTHROPIC_BASE_URL: baseURL, ANTHROPIC_API_KEY: 'local-fixture-not-a-credential',
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', DISABLE_AUTOUPDATER: '1',
    DISABLE_TELEMETRY: '1', DISABLE_ERROR_REPORTING: '1',
    HTTP_PROXY: baseURL, HTTPS_PROXY: baseURL, ALL_PROXY: baseURL,
    NO_PROXY: '127.0.0.1,localhost',
    PATRONUS_FIXTURE_DIRECTORY: directory, PATRONUS_FIXTURE_POLICY: policy,
  };
  if (runtime?.isolatedDataDir || !runtime || process.env.PATRONUS_DATA_DIR) {
    env.PATRONUS_DATA_DIR = runtime?.isolatedDataDir
      ? await mkdtemp(join(process.platform === 'darwin' ? '/private/tmp' : tmpdir(), 'pcl-'))
      : process.env.PATRONUS_DATA_DIR || await mkdtemp(join(process.platform === 'darwin' ? '/private/tmp' : tmpdir(), 'pcl-'));
  }
  if (runtime) {
    const stateRoot = process.env.PATRONUS_CLAUDE_STATE_ROOT || join(tmpdir(), 'patronus-claude-native-state');
    await mkdir(stateRoot, { recursive: true });
    env.PATRONUS_NATIVE_STATE_DIR = await mkdtemp(join(stateRoot, 'broker-state-'));
    env.PATRONUS_SCANNER_BIN = runtime.scanner || process.env.PATRONUS_PROOF_SCANNER || 'patronus-security-scanner';
    env.PATRONUS_RESPONSE_WAIT_MS = String(runtime.responseWaitMs ?? 500);
  }
  async function invoke(extra = []) {
    let stdout = '', stderr = '', timedOut = false;
    const child = spawn(process.env.PATRONUS_CLAUDE_BINARY || 'claude', [
      '--print', '--verbose', '--output-format', 'stream-json',
      '--model', 'claude-sonnet-4-20250514', '--system-prompt', 'Local scripted hook contract test.',
      '--settings', join(directory, 'settings.json'), '--setting-sources', '',
      ...(!plugin ? ['--strict-mcp-config'] : []), '--mcp-config', join(directory, 'mcp.json'), '--no-chrome',
      '--tools', 'Bash,Read', '--allowedTools', [`Bash,Read,${tool}`, ...(plugin ? patronusTools : [])].join(','), '--permission-mode', 'dontAsk',
      ...(plugin ? ['--plugin-dir', join(directory, 'plugin')] : []),
      ...extra,
      userPrompt,
    ], { cwd: directory, env, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    child.stdout.on('data', part => { stdout += part; });
    child.stderr.on('data', part => { stderr += part; });
    const timer = setTimeout(() => {
      timedOut = true;
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Already exited. */ }
    }, timeout);
    const exitCode = await new Promise((ok, fail) => { child.once('error', fail); child.once('close', ok); });
    clearTimeout(timer);
    return { stdout, stderr, exitCode, timedOut };
  }
  try {
    const runs = [await invoke()];
    if (resume) {
      const init = runs[0].stdout.trim().split('\n').map(JSON.parse).find(event => event.subtype === 'init');
      if (!init?.session_id) throw new Error(`No session to resume: ${directory}`);
      runs.push(await invoke(['--resume', init.session_id]));
    }
    const stdout = runs.map(run => run.stdout).join('');
    const stderr = runs.map(run => run.stderr).join('');
    await writeFile(join(directory, 'requests.json'), JSON.stringify(requests, null, 2));
    await writeFile(join(directory, 'transcript.jsonl'), stdout);
    await writeFile(join(directory, 'stderr.txt'), stderr);
    return { directory, messages, requests, stdout, stderr, runs,
      nativeStateDir: env.PATRONUS_NATIVE_STATE_DIR, dataDir: env.PATRONUS_DATA_DIR,
      exitCode: runs.at(-1).exitCode, timedOut: runs.some(run => run.timedOut) };
  } finally {
    server.closeAllConnections();
    await new Promise(ok => server.close(ok));
  }
}

export { quote };
