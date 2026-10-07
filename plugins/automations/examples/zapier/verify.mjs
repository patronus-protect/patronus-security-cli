#!/usr/bin/env node
// Triggers the chatbot and RAG Zaps through their Catch Hook URLs and checks the LLM log in
// Storage by Zapier: allowed inputs must be stored exactly as released by Patronus Guard,
// rejected inputs must never reach the LLM step (no record), and RAG must retrieve the
// expected document. Reads ZAPIER_HOOK_CHATBOT, ZAPIER_HOOK_RAG and ZAPIER_STORAGE_SECRET.
import { readFile, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';

const { values: args } = parseArgs({ options: {
  flow: { type: 'string', default: 'all' }, only: { type: 'string' }, report: { type: 'string' },
  wait: { type: 'string', default: '90' },
} });
const hooks = { chatbot: process.env.ZAPIER_HOOK_CHATBOT, rag: process.env.ZAPIER_HOOK_RAG };
const secret = process.env.ZAPIER_STORAGE_SECRET;
if (!secret) throw new Error('Set ZAPIER_STORAGE_SECRET.');
const flows = args.flow === 'all' ? ['chatbot', 'rag'] : [args.flow];
const cases = JSON.parse(await readFile(new URL('../data/cases.json', import.meta.url), 'utf8'));

async function stored(key) {
  const url = new URL('https://store.zapier.com/api/records');
  url.searchParams.set('secret', secret);
  url.searchParams.set('key', key);
  const response = await fetch(url, { signal: AbortSignal.timeout(20_000) });
  if (!response.ok) throw new Error(`Storage by Zapier HTTP ${response.status}`);
  return (await response.json())[key];
}

const runs = [];
for (const flow of flows) {
  if (!hooks[flow]) throw new Error(`Set ZAPIER_HOOK_${flow.toUpperCase()}.`);
  for (const item of cases[flow]) {
    if (args.only && item.id !== args.only) continue;
    const caseId = `${item.id}-${Date.now()}`;
    const body = flow === 'chatbot' ? { case_id: caseId, message: item.message } : { case_id: caseId, question: item.question };
    const response = await fetch(hooks[flow], { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!response.ok) throw new Error(`Catch Hook ${flow} HTTP ${response.status}`);
    runs.push({ flow, item, caseId });
  }
}

// Zaps run asynchronously: poll until every allowed case has reached the LLM step or time runs out.
const deadline = Date.now() + Number(args.wait) * 1000;
const llm = new Map();
while (Date.now() < deadline) {
  for (const run of runs) if (!llm.has(run.caseId)) {
    const value = await stored(`llm:${run.caseId}`);
    if (value !== undefined && value !== null) llm.set(run.caseId, value);
  }
  if (runs.filter(run => run.item.expect === 'allow').every(run => llm.has(run.caseId))) break;
  await new Promise(resolve => setTimeout(resolve, 5000));
}
// Give rejected cases the same window so a late LLM call would still be detected.
await new Promise(resolve => setTimeout(resolve, Math.max(0, Math.min(15_000, deadline - Date.now()))));

const results = [];
for (const { flow, item, caseId } of runs) {
  const llmInput = llm.get(caseId) ?? await stored(`llm:${caseId}`);
  const problems = [];
  if (item.expect === 'allow') {
    if (llmInput === undefined || llmInput === null) problems.push('LLM step was not reached');
    else if (flow === 'chatbot' && llmInput !== item.message) problems.push('LLM input differs from the chat message');
    else if (flow === 'rag' && !String(llmInput).includes(item.question)) problems.push('LLM input does not contain the question');
  } else if (llmInput !== undefined && llmInput !== null) problems.push('LLM step received text for a rejected input');
  if (flow === 'rag' && item.expect_document) {
    const retrieved = String(await stored(`retrieved:${caseId}`) ?? '');
    if (!retrieved.split(',').includes(item.expect_document)) problems.push(`retrieval missed ${item.expect_document} (got ${retrieved || 'nothing'})`);
  }
  const status = llmInput === undefined || llmInput === null ? 'not_called' : 'llm_called';
  results.push({ flow, id: item.id, expect: item.expect, status, pass: !problems.length, problems });
  console.log(`${problems.length ? 'FAIL' : 'PASS'}  ${flow.padEnd(7)} ${item.id.padEnd(22)} expect=${item.expect.padEnd(6)} got=${status}${problems.length ? `  -> ${problems.join('; ')}` : ''}`);
}
const failed = results.filter(result => !result.pass).length;
console.log(`\n${results.length - failed}/${results.length} cases passed`);
if (args.report) await writeFile(args.report, `${JSON.stringify({ at: new Date().toISOString(), results }, null, 2)}\n`);
process.exitCode = failed ? 1 : 0;
