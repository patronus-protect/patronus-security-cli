// Local, deterministic hook fixture. No model, network, or shared-runtime calls.
import { appendFile, writeFile, access } from 'node:fs/promises';
import { join } from 'node:path';
import { mapClaude, supportsClaudeResponse } from '../../native/src/hosts/claude.ts';

let raw = '';
for await (const part of process.stdin) raw += part;
const event = JSON.parse(raw);
await appendFile(join(process.env.PATRONUS_FIXTURE_DIRECTORY, 'hooks.jsonl'), JSON.stringify(event) + '\n');
const policy = process.env.PATRONUS_FIXTURE_POLICY;
const quarantine = join(process.env.PATRONUS_FIXTURE_DIRECTORY, 'quarantined');
let decision;
if (policy === 'deny' && event.hook_event_name === 'PreToolUse') {
  decision = { kind: 'deny', text: 'PATRONUS_REQUEST_DENIED' };
}
if (policy === 'prompt-block' && event.hook_event_name === 'UserPromptSubmit') {
  decision = { kind: 'stop', text: 'PATRONUS_PROMPT_BLOCKED' };
}
const ownTools = new Set(['mcp__patronus__', 'mcp__plugin_patronus-security_patronus__'].flatMap(prefix =>
  ['patronus_check_result', 'patronus_read_redacted', 'patronus_scan'].map(name => prefix + name)));
if (policy === 'placeholder' && event.hook_event_name === 'PreToolUse' && ownTools.has(event.tool_name)) {
  // The real controller supplies broker results. This fixture proves the native transport.
  await appendFile(join(process.env.PATRONUS_FIXTURE_DIRECTORY, 'broker-requests.jsonl'), JSON.stringify({
    tool_name: event.tool_name, session_id: event.session_id, arguments: event.tool_input,
  }) + '\n');
  decision = { kind: 'replace', text: 'PATRONUS_SAFE_BROKER_RESULT' };
}
if (policy === 'pending' && event.hook_event_name === 'PostToolUse') {
  decision = { kind: 'replace', text: 'PATRONUS_PENDING_RECEIPT' };
  if (!supportsClaudeResponse(event)) {
    await writeFile(quarantine, 'PATRONUS_SESSION_QUARANTINED');
    decision = { kind: 'stop', text: 'PATRONUS_SESSION_QUARANTINED' };
  }
}
if (policy === 'post-timeout' && event.hook_event_name === 'PostToolUse') {
  await new Promise(resolve => setTimeout(resolve, 3000));
}
if (policy === 'error-stop' && event.hook_event_name === 'PostToolUseFailure') {
  await writeFile(quarantine, 'PATRONUS_SESSION_QUARANTINED');
  decision = { kind: 'stop', text: 'PATRONUS_SESSION_QUARANTINED' };
}
if (policy === 'post-timeout' && event.hook_event_name === 'PostToolBatch' &&
    event.tool_calls.some(call => !JSON.stringify(call.tool_response).includes('PATRONUS_PENDING_RECEIPT'))) {
  await writeFile(quarantine, 'PATRONUS_SESSION_QUARANTINED');
}
if (['PostToolBatch', 'UserPromptSubmit'].includes(event.hook_event_name)) {
  const blocked = await access(quarantine).then(() => true, () => false);
  if (blocked) decision = { kind: 'stop', text: 'PATRONUS_SESSION_QUARANTINED' };
}
const output = decision ? mapClaude(event.hook_event_name, decision, event) : {};
await appendFile(join(process.env.PATRONUS_FIXTURE_DIRECTORY, 'hook-outputs.jsonl'), JSON.stringify({ event: event.hook_event_name, output }) + '\n');
process.stdout.write(JSON.stringify(output) + '\n');
