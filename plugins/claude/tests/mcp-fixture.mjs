// A deterministic stdio MCP peer; only synthetic text/JSON is returned.
import { createInterface } from 'node:readline';
import { appendFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';

const tools = ['read_text', 'read_json', 'read_mixed', 'read_structured', 'read_error', 'read_source_error', 'patronus_check_result', 'patronus_read_redacted', 'patronus_scan'].map(name => ({
  name, description: 'Local hook proof fixture.',
  inputSchema: { type: 'object', properties: { scan_id: { type: 'string' } }, additionalProperties: true },
  annotations: { readOnlyHint: true },
}));

for await (const line of createInterface({ input: process.stdin })) {
  if (!line.trim()) continue;
  const message = JSON.parse(line);
  if (message.id === undefined) continue;
  let result;
  if (message.method === 'initialize') {
    result = { protocolVersion: message.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'local-fixture', version: '1' } };
  } else if (message.method === 'tools/list') {
    result = { tools };
  } else if (message.method === 'tools/call') {
    await appendFile(join(process.env.PATRONUS_FIXTURE_DIRECTORY, 'mcp-executions.jsonl'), JSON.stringify(message.params) + '\n');
    const data = { payload: 'RAW_RESPONSE_ONLY_SENTINEL' };
    result = message.params.name === 'read_structured'
      ? { content: [{ type: 'text', text: JSON.stringify(data) }, { type: 'text', text: 'RAW_ADDITIONAL_BLOCK_SENTINEL' }],
        structuredContent: { payload: 'RAW_STRUCTURED_ONLY_SENTINEL' }, _meta: { canary: 'RAW_META_ONLY_SENTINEL' } }
      : message.params.name === 'read_mixed'
        ? { content: [
          { type: 'text', text: JSON.stringify(data) },
          { type: 'image', data: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jG2kAAAAASUVORK5CYII=', mimeType: 'image/png' },
          { type: 'text', text: 'RAW_ADDITIONAL_BLOCK_SENTINEL' },
        ] }
      : { content: [{ type: 'text', text: message.params.name === 'read_json' ? JSON.stringify(data) : 'RAW_RESPONSE_ONLY_SENTINEL' }] };
    if (message.params.name === 'read_error') result = {
      content: [{ type: 'text', text: 'The requested fixture record is unavailable.' }], isError: true,
    };
    if (message.params.name === 'read_source_error') result = {
      content: [{ type: 'text', text: await readFile(join(process.env.PATRONUS_FIXTURE_DIRECTORY, 'source.txt'), 'utf8') }], isError: true,
    };
  } else {
    result = {};
  }
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }) + '\n');
}
