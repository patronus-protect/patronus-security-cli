#!/usr/bin/env node
// Runs the shared chatbot and RAG cases against the imported n8n workflows and
// proves, through the recording LLM stub, that the LLM received exactly the
// guarded text for allowed inputs and was never called for rejected inputs.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { parseArgs } from 'node:util';

const { values: args } = parseArgs({ options: {
  n8n: { type: 'string', default: 'http://127.0.0.1:5678' },
  stub: { type: 'string', default: 'http://127.0.0.1:4100' },
  flow: { type: 'string', default: 'all' },
  only: { type: 'string' },
  report: { type: 'string' },
} });

const cases = JSON.parse(await readFile(new URL('../data/cases.json', import.meta.url), 'utf8'));
const flows = args.flow === 'all' ? ['chatbot', 'rag'] : [args.flow];

async function json(url, init) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(120_000) });
  const text = await response.text();
  let body;
  try { body = JSON.parse(text); } catch { body = { raw: text }; }
  return { status: response.status, body: Array.isArray(body) ? body[0] : body };
}

const stubCalls = async caseId => (await json(`${args.stub}/calls`)).body.calls.filter(call => call.case_id === caseId);

function check(flow, item, response, calls) {
  const problems = [];
  const body = response.body ?? {};
  if (response.status !== 200) problems.push(`webhook HTTP ${response.status}`);
  if (item.expect === 'allow') {
    if (body.status !== 'allowed') problems.push(`expected allowed, got ${body.status ?? 'no status'}${body.error ? ` (${body.error})` : ''}`);
    if (calls.length !== 1) problems.push(`expected exactly 1 LLM call, got ${calls.length}`);
    const received = calls[0]?.messages?.at(-1)?.content;
    if (calls.length && received !== body.llm_input) problems.push('LLM input differs from the guarded text');
    if (flow === 'chatbot' && body.llm_input !== undefined && body.llm_input !== item.message) problems.push('guarded text differs from the chat message');
    if (flow === 'rag' && body.llm_input !== undefined && !body.llm_input.includes(item.question)) problems.push('guarded prompt does not contain the question');
  } else {
    if (!['blocked', 'unverified'].includes(body.status)) problems.push(`expected blocked/unverified, got ${body.status ?? 'no status'}`);
    if (calls.length) problems.push(`LLM was called ${calls.length} time(s) for a rejected input`);
  }
  if (flow === 'rag' && item.expect_document && !(body.retrieved ?? []).includes(item.expect_document)) {
    problems.push(`retrieval missed ${item.expect_document} (got ${(body.retrieved ?? []).join(', ') || 'nothing'})`);
  }
  return problems;
}

// n8n reports healthy before published workflows have registered their webhooks.
async function waitForWebhook(flow) {
  for (let attempt = 0; attempt < 60; attempt++) {
    const response = await fetch(`${args.n8n}/webhook/patronus-${flow}`, { method: 'OPTIONS' }).catch(() => null);
    if (response && response.status !== 404) return;
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  throw new Error(`webhook patronus-${flow} is not registered; is the workflow published and n8n running?`);
}

const results = [];
for (const flow of flows) {
  await waitForWebhook(flow);
  for (const item of cases[flow]) {
    if (args.only && item.id !== args.only) continue;
    const caseId = `${item.id}-${Date.now()}`;
    const payload = flow === 'chatbot' ? { case_id: caseId, message: item.message } : { case_id: caseId, question: item.question };
    const started = Date.now();
    const response = await json(`${args.n8n}/webhook/patronus-${flow}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    });
    const calls = await stubCalls(caseId);
    const problems = check(flow, item, response, calls);
    results.push({
      flow, id: item.id, expect: item.expect, status: response.body?.status ?? null, llm_calls: calls.length,
      retrieved: response.body?.retrieved, ms: Date.now() - started, pass: problems.length === 0, problems,
      error: response.body?.error,
    });
    const last = results.at(-1);
    console.log(`${last.pass ? 'PASS' : 'FAIL'}  ${flow.padEnd(7)} ${item.id.padEnd(22)} expect=${item.expect.padEnd(6)} got=${String(last.status).padEnd(10)} llm_calls=${calls.length}${problems.length ? `  -> ${problems.join('; ')}` : ''}`);
  }
}

const failed = results.filter(result => !result.pass).length;
console.log(`\n${results.length - failed}/${results.length} cases passed`);
if (args.report) {
  await mkdir(dirname(args.report), { recursive: true });
  await writeFile(args.report, `${JSON.stringify({ at: new Date().toISOString(), n8n: args.n8n, results }, null, 2)}\n`);
}
process.exitCode = failed ? 1 : 0;
