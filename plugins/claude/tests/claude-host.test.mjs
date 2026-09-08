import test from 'node:test';
import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { runHost, quote } from './scripted-host.mjs';

test('UserPromptSubmit exposes the exact user text before the first model request', { timeout: 40000 }, async () => {
  const prompt = '{"task":"scan this exact raw prompt"}';
  const result = await runHost({
    name: 'prompt-shape', tool: 'Read', input: {}, policy: 'prompt-block', userPrompt: prompt,
  });
  assert.equal(result.timedOut, false, `host timed out: ${result.directory}`);
  assert.equal(result.messages.length, 0, `blocked prompt reached the model: ${result.directory}`);
  const events = (await readFile(join(result.directory, 'hooks.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  const event = events.find(value => value.hook_event_name === 'UserPromptSubmit');
  assert.equal(event.prompt, prompt);
  process.stdout.write(`proof: ${result.directory}\n`);
});

test('PreToolUse denial prevents a real Bash execution', { timeout: 40000 }, async () => {
  const result = await runHost({
    name: 'request-deny', tool: 'Bash', policy: 'deny',
    input: directory => ({ command: `printf executed > ${quote(join(directory, 'executed'))}` }),
  });
  assert.equal(result.timedOut, false, `host timed out: ${result.directory}`);
  assert.equal(result.exitCode, 0, `host did not finish: ${result.directory}`);
  assert.equal(result.messages.length, 2, `unexpected model request count: ${result.directory}`);
  await assert.rejects(access(join(result.directory, 'executed')), { code: 'ENOENT' });
  assert.match(JSON.stringify(result.messages[1]), /PATRONUS_REQUEST_DENIED/);
  const events = (await readFile(join(result.directory, 'hooks.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.ok(!events.some(event => event.hook_event_name === 'PostToolUseFailure'), 'PreToolUse denial must not quarantine through a failure hook');
  process.stdout.write(`proof: ${result.directory}\n`);
});

test('Read fixture observes the actual installed text output shape', { timeout: 40000 }, async () => {
  const result = await runHost({
    name: 'read-shape', tool: 'Read', policy: 'pass', input: (_directory, source) => ({ file_path: source }),
  });
  assert.equal(result.exitCode, 0, `host did not finish: ${result.directory}`);
  assert.equal(result.messages.length, 2);
  const events = (await readFile(join(result.directory, 'hooks.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  const response = events.find(event => event.hook_event_name === 'PostToolUse').tool_response;
  assert.equal(response.type, 'text');
  assert.match(JSON.stringify(result.messages[1]), /RAW_RESPONSE_ONLY_SENTINEL/);
  process.stdout.write(`Read schema keys: ${Object.keys(response).join(',')}; file: ${Object.keys(response.file || {}).join(',')}\n`);
  process.stdout.write(`proof: ${result.directory}\n`);
});

test('tool errors add an inactive warning and continue to the next model request', { timeout: 40000 }, async () => {
  const result = await runHost({
    name: 'read-error-degraded', tool: 'Read', policy: 'error-stop', batch: true,
    input: directory => ({ file_path: join(directory, 'missing.txt') }),
  });
  assert.equal(result.timedOut, false, `host timed out: ${result.directory}`);
  assert.equal(result.messages.length, 2, `warning did not preserve the next model request: ${result.directory}`);
  assert.match(JSON.stringify(result.messages[1]), /No security scan was completed/);
  const events = (await readFile(join(result.directory, 'hooks.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.ok(events.some(event => event.hook_event_name === 'PostToolUseFailure'));
  assert.ok(events.some(event => event.hook_event_name === 'PostToolBatch'));
  process.stdout.write(`proof: ${result.directory}\n`);
});

test('PostToolUseFailure preserves the original error and adds warning context', { timeout: 40000 }, async () => {
  const result = await runHost({
    name: 'failure-without-batch', tool: 'Read', policy: 'error-stop', batch: false,
    input: directory => ({ file_path: join(directory, 'missing.txt') }),
  });
  assert.equal(result.messages.length, 2, `unexpected failure-only behavior: ${result.directory}`);
  assert.ok(result.messages[1].messages.some(message => JSON.stringify(message).includes('is_error')));
  const events = (await readFile(join(result.directory, 'hooks.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  const failure = events.find(event => event.hook_event_name === 'PostToolUseFailure');
  assert.equal(typeof failure.error, 'string');
  assert.ok(result.messages[1].messages.some(message => JSON.stringify(message).includes(failure.error)));
  assert.match(JSON.stringify(result.messages[1]), /No security scan was completed/);
  process.stdout.write(`negative control: ${result.directory}\n`);
});

test('successful Read text output is replaced with pending in a schema-valid result', { timeout: 40000 }, async () => {
  const result = await runHost({
    name: 'read-pending', tool: 'Read', policy: 'pending', input: (_directory, source) => ({ file_path: source }),
  });
  assert.equal(result.exitCode, 0, `host did not finish: ${result.directory}`);
  assert.equal(result.messages.length, 2);
  assert.doesNotMatch(JSON.stringify(result.messages), /RAW_RESPONSE_ONLY_SENTINEL/);
  assert.match(JSON.stringify(result.messages[1]), /PATRONUS_PENDING_RECEIPT/);
  assert.doesNotMatch(result.stdout, /RAW_RESPONSE_ONLY_SENTINEL/);
  process.stdout.write(`proof: ${result.directory}\n`);
});

test('successful Bash output is replaced with pending before the next model request', { timeout: 40000 }, async () => {
  const result = await runHost({
    name: 'bash-pending', tool: 'Bash', policy: 'pending',
    input: (_directory, source) => ({ command: `cat ${quote(source)}` }),
  });
  assert.equal(result.timedOut, false, `host timed out: ${result.directory}`);
  assert.equal(result.exitCode, 0, `host did not finish: ${result.directory}`);
  assert.equal(result.messages.length, 2, `unexpected model request count: ${result.directory}`);
  assert.doesNotMatch(JSON.stringify(result.messages), /RAW_RESPONSE_ONLY_SENTINEL/);
  assert.match(JSON.stringify(result.messages[1]), /PATRONUS_PENDING_RECEIPT/);
  assert.doesNotMatch(result.stdout, /RAW_RESPONSE_ONLY_SENTINEL/);
  process.stdout.write(`proof: ${result.directory}\n`);
});

for (const shape of ['text', 'json']) {
  test(`successful MCP ${shape} output is replaced with pending before the next model request`, { timeout: 40000 }, async () => {
    const result = await runHost({
      name: `mcp-${shape}-pending`, tool: `mcp__fixture__read_${shape}`, input: {}, policy: 'pending', mcp: true,
    });
    assert.equal(result.exitCode, 0, `host did not finish: ${result.directory}`);
    assert.equal(result.messages.length, 2);
    assert.doesNotMatch(JSON.stringify(result.messages), /RAW_RESPONSE_ONLY_SENTINEL/);
    assert.match(JSON.stringify(result.messages[1]), /PATRONUS_PENDING_RECEIPT/);
    assert.doesNotMatch(result.stdout, /RAW_RESPONSE_ONLY_SENTINEL/);
    const calls = (await readFile(join(result.directory, 'mcp-executions.jsonl'), 'utf8')).trim().split('\n');
    assert.equal(calls.length, 1);
    process.stdout.write(`proof: ${result.directory}\n`);
  });
}

test('mixed MCP text and media exposes every ordered text block in PostToolUse', { timeout: 40000 }, async () => {
  const result = await runHost({
    name: 'mcp-mixed-shape', tool: 'mcp__fixture__read_mixed', input: {}, policy: 'pass', mcp: true,
  });
  assert.equal(result.exitCode, 0, `host did not finish: ${result.directory}`);
  const events = (await readFile(join(result.directory, 'hooks.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  const response = events.find(event => event.hook_event_name === 'PostToolUse').tool_response;
  assert.deepEqual(response.map(block => block.type), ['text', 'image', 'text']);
  assert.deepEqual(response.filter(block => block.type === 'text').map(block => block.text), [
    '{"payload":"RAW_RESPONSE_ONLY_SENTINEL"}', 'RAW_ADDITIONAL_BLOCK_SENTINEL',
  ]);
  const next = result.messages[1].messages.at(-1).content.find(block => block.type === 'tool_result').content;
  assert.deepEqual(next, response);
  process.stdout.write(`proof: ${result.directory}\n`);
});

test('own placeholder is denied with safe broker data and authoritative hook session ID', { timeout: 40000 }, async () => {
  const result = await runHost({
    name: 'own-placeholder', tool: 'mcp__patronus__patronus_check_result', policy: 'placeholder', mcp: 'patronus',
    input: { scan_id: 'opaque-job', session_id: 'forged-model-session' },
  });
  assert.equal(result.exitCode, 0, `host did not finish: ${result.directory}`);
  assert.equal(result.messages.length, 2);
  await assert.rejects(access(join(result.directory, 'mcp-executions.jsonl')), { code: 'ENOENT' });
  const call = JSON.parse((await readFile(join(result.directory, 'broker-requests.jsonl'), 'utf8')).trim());
  assert.notEqual(call.session_id, 'forged-model-session');
  assert.equal(call.arguments.session_id, 'forged-model-session');
  assert.match(JSON.stringify(result.messages[1]), /PATRONUS_SAFE_BROKER_RESULT/);
  assert.doesNotMatch(JSON.stringify(result.messages), /RAW_RESPONSE_ONLY_SENTINEL/);
  const events = (await readFile(join(result.directory, 'hooks.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.ok(!events.some(event => event.hook_event_name === 'PostToolUseFailure'), 'Placeholder denial must not produce PostToolUseFailure');
  process.stdout.write(`proof: ${result.directory}\n`);
});

test('shipped plugin configuration discovers hooks and its exact MCP namespace', { timeout: 40000 }, async () => {
  const result = await runHost({
    name: 'plugin-wiring', tool: 'mcp__plugin_patronus-security_patronus__patronus_check_result',
    input: { scan_id: 'opaque-job' }, policy: 'placeholder', plugin: true,
  });
  assert.equal(result.timedOut, false);
  assert.equal(result.exitCode, 0, `plugin did not finish: ${result.directory}`);
  assert.equal(result.messages.length, 2, `plugin hook dispatch failed: ${result.directory}`);
  assert.ok(result.messages[0].tools.some(tool => tool.name === 'mcp__plugin_patronus-security_patronus__patronus_check_result'));
  await assert.rejects(access(join(result.directory, 'mcp-executions.jsonl')), { code: 'ENOENT' });
  assert.match(JSON.stringify(result.messages[1]), /PATRONUS_SAFE_BROKER_RESULT/);
  const events = (await readFile(join(result.directory, 'hooks.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  const declared = JSON.parse(await readFile(join(result.directory, 'plugin', 'hooks', 'hooks.json'), 'utf8')).hooks;
  for (const event of ['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse']) {
    assert.ok(declared[event], `plugin manifest did not declare ${event}`);
  }
  for (const event of ['SessionStart', 'UserPromptSubmit', 'PreToolUse']) {
    assert.ok(events.some(input => input.hook_event_name === event), `plugin did not register ${event}`);
  }
  process.stdout.write(`plugin discovery proof: ${result.directory}\n`);
});

test('a warned error does not poison a resumed session', { timeout: 70000 }, async () => {
  const result = await runHost({
    name: 'error-resume', tool: 'Read', policy: 'error-stop', batch: true, resume: true,
    input: directory => ({ file_path: join(directory, 'missing.txt') }),
  });
  assert.equal(result.timedOut, false);
  assert.equal(result.runs.length, 2);
  assert.equal(result.messages.length, 3, `resume did not remain usable: ${result.directory}`);
  assert.match(JSON.stringify(result.messages[1]), /No security scan was completed/);
  process.stdout.write(`proof: ${result.directory}\n`);
});

test('unsupported successful Read image result warns and remains available', { timeout: 40000 }, async () => {
  const result = await runHost({
    name: 'unsupported-image', tool: 'Read', policy: 'pending',
    input: directory => ({ file_path: join(directory, 'image.png') }),
  });
  assert.equal(result.timedOut, false);
  assert.equal(result.messages.length, 2, `unsupported result did not continue: ${result.directory}`);
  assert.match(JSON.stringify(result.messages[1]), /No security scan was completed/);
  const events = (await readFile(join(result.directory, 'hooks.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(events.find(event => event.hook_event_name === 'PostToolUse')?.tool_response.type, 'image');
  process.stdout.write(`proof: ${result.directory}\n`);
});

test('a timed-out response hook does not make the chat unusable', { timeout: 40000 }, async () => {
  const result = await runHost({
    name: 'post-timeout', tool: 'Read', policy: 'post-timeout', batch: true, postHookTimeout: 1,
    input: (_directory, source) => ({ file_path: source }),
  });
  assert.equal(result.timedOut, false);
  assert.equal(result.messages.length, 2, `timed-out post hook stopped the chat: ${result.directory}`);
  assert.match(JSON.stringify(result.messages[1]), /RAW_RESPONSE_ONLY_SENTINEL/);
  process.stdout.write(`proof: ${result.directory}\n`);
});

test('MCP structuredContent is retained outside the hook projection (boundary control)', { timeout: 40000 }, async () => {
  const result = await runHost({
    name: 'mcp-structured-boundary', tool: 'mcp__fixture__read_structured', input: {}, policy: 'pending', mcp: true,
  });
  assert.equal(result.messages.length, 2);
  assert.doesNotMatch(JSON.stringify(result.messages), /RAW_(?:RESPONSE_ONLY|STRUCTURED_ONLY|META_ONLY|ADDITIONAL_BLOCK)_SENTINEL/);
  assert.equal(result.stdout.includes('RAW_STRUCTURED_ONLY_SENTINEL'), true, 'Installed behavior changed; reassess the metadata limitation.');
  process.stdout.write(`uncovered transcript metadata: ${result.directory}\n`);
});
