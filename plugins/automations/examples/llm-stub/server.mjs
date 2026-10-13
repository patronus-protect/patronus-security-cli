#!/usr/bin/env node
// Recording LLM test service with an OpenAI-compatible chat endpoint.
// Every call is appended to a JSONL log so tests can prove what the LLM received.
// Set LLM_UPSTREAM (for example http://127.0.0.1:11434 for Ollama) to forward
// calls to a real model while still recording them.
import { createServer } from 'node:http';
import { appendFile, readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const port = Number(process.env.LLM_STUB_PORT ?? 4100);
const host = process.env.LLM_STUB_HOST ?? '127.0.0.1';
const log = resolve(process.env.LLM_STUB_LOG ?? 'llm-calls.jsonl');
const upstream = process.env.LLM_UPSTREAM?.replace(/\/+$/, '');

async function calls() {
  try {
    return (await readFile(log, 'utf8')).split('\n').filter(Boolean).map(line => JSON.parse(line));
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 2_000_000) throw new Error('request too large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

async function complete(body) {
  if (!upstream) {
    const last = body.messages?.at(-1)?.content ?? '';
    return { content: `[llm-stub] received ${String(last).length} characters`, model: 'llm-stub' };
  }
  const response = await fetch(`${upstream}/v1/chat/completions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...body, stream: false }),
    signal: AbortSignal.timeout(120_000),
  });
  if (!response.ok) throw new Error(`upstream HTTP ${response.status}`);
  const data = await response.json();
  return { content: data.choices?.[0]?.message?.content ?? '', model: data.model ?? body.model };
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (req.method === 'GET' && url.pathname === '/health') return send(res, 200, { ok: true, upstream: upstream ?? null });
    if (req.method === 'GET' && url.pathname === '/calls') return send(res, 200, { calls: await calls() });
    if (req.method === 'DELETE' && url.pathname === '/calls') {
      await writeFile(log, '');
      return send(res, 200, { cleared: true });
    }
    if (req.method === 'POST' && url.pathname === '/v1/chat/completions') {
      const body = await readBody(req);
      if (!Array.isArray(body.messages) || !body.messages.length) return send(res, 400, { error: 'messages required' });
      const result = await complete(body);
      const entry = {
        at: new Date().toISOString(),
        case_id: req.headers['x-case-id'] ?? body.user ?? null,
        model: body.model ?? null,
        messages: body.messages,
        reply: result.content,
      };
      await mkdir(dirname(log), { recursive: true });
      await appendFile(log, `${JSON.stringify(entry)}\n`);
      return send(res, 200, {
        id: `chatcmpl-stub-${Date.now()}`, object: 'chat.completion', created: Math.floor(Date.now() / 1000), model: result.model,
        choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: result.content } }],
      });
    }
    send(res, 404, { error: 'not found' });
  } catch (error) {
    send(res, 500, { error: error.message });
  }
});

server.listen(port, host, () => console.log(`llm-stub listening on http://${host}:${port} (log: ${log}${upstream ? `, upstream: ${upstream}` : ''})`));
