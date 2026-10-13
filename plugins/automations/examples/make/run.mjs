#!/usr/bin/env node
// Deploys the Make example scenarios and runs the shared cases through the Make API.
//   node examples/make/run.mjs deploy --connection 11680199
//   node examples/make/run.mjs verify
// Reads MAKE_API_TOKEN, MAKE_ZONE (default eu1.make.com) and MAKE_TEAM_ID from the environment.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { parseArgs } from 'node:util';

const { positionals, values: args } = parseArgs({ allowPositionals: true, options: {
  connection: { type: 'string' }, flow: { type: 'string', default: 'all' }, only: { type: 'string' },
  state: { type: 'string', default: new URL('../../../../tmp/make-examples.json', import.meta.url).pathname },
  report: { type: 'string' },
} });
const zone = process.env.MAKE_ZONE ?? 'eu1.make.com';
const team = Number(process.env.MAKE_TEAM_ID);
const token = process.env.MAKE_API_TOKEN;
if (!token || !team) throw new Error('Set MAKE_API_TOKEN and MAKE_TEAM_ID.');

async function make(method, path, body) {
  const response = await fetch(`https://${zone}/api/v2${path}`, {
    method, redirect: 'error', signal: AbortSignal.timeout(120_000),
    headers: { Authorization: `Token ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`Make ${method} ${path} failed (HTTP ${response.status}, code ${data.code ?? 'n/a'}): ${[data.message, data.detail, JSON.stringify(data.suberrors ?? '')].filter(Boolean).join(' | ').slice(0, 600)}`);
  return data;
}

const flows = args.flow === 'all' ? ['chatbot', 'rag'] : [args.flow];

const LOG_FIELDS = ['case_id', 'status', 'llm_input', 'retrieved'];

async function ensureLogStore(state) {
  if (state.datastore) return state.datastore;
  const structure = await make('POST', '/data-structures', {
    teamId: team, name: 'Patronus example LLM log', strict: false,
    spec: LOG_FIELDS.map(name => ({ name, label: name, type: 'text', required: false })),
  });
  const store = await make('POST', '/data-stores', {
    teamId: team, name: 'Patronus example LLM log', datastructureId: structure.dataStructure.id, maxSizeMB: 1,
  });
  return store.dataStore.id;
}

async function deploy() {
  const connection = Number(args.connection);
  if (!Number.isSafeInteger(connection)) throw new Error('Pass --connection <Make connection id>.');
  const state = JSON.parse(await readFile(args.state, 'utf8').catch(() => '{}'));
  state.datastore = await ensureLogStore(state);
  for (const flow of flows) {
    const { blueprint, interface: scenarioInterface } = JSON.parse(await readFile(new URL(`${flow}.blueprint.json`, import.meta.url), 'utf8'));
    const bound = JSON.stringify(blueprint)
      .replaceAll('"{{CONNECTION_ID}}"', String(connection))
      .replaceAll('"{{DATASTORE_ID}}"', String(state.datastore));
    let id = state[flow];
    if (id) await make('PATCH', `/scenarios/${id}?confirmed=true`, { blueprint: bound });
    else {
      const created = await make('POST', '/scenarios?confirmed=true', {
        teamId: team, blueprint: bound, scheduling: JSON.stringify({ type: 'on-demand' }),
      });
      id = created.scenario.id;
    }
    await make('PATCH', `/scenarios/${id}/interface`, { interface: scenarioInterface });
    // On-demand scenarios must be active before the API can run them.
    await make('POST', `/scenarios/${id}/start`).catch(error => { if (!/IM306|already/i.test(error.message)) throw error; });
    state[flow] = id;
    console.log(`deployed ${flow} as scenario ${id}`);
  }
  await mkdir(new URL('../../../../tmp/', import.meta.url), { recursive: true });
  await writeFile(args.state, `${JSON.stringify(state, null, 2)}\n`);
}

// The run API returns no scenario outputs, so each run is checked through the LLM log record.
async function logRecord(state, key) {
  const data = await make('GET', `/data-stores/${state.datastore}/data?pg%5Blimit%5D=100`);
  return data.records?.find(record => record.key === key)?.data;
}

async function verify() {
  const state = JSON.parse(await readFile(args.state, 'utf8'));
  const cases = JSON.parse(await readFile(new URL('../data/cases.json', import.meta.url), 'utf8'));
  const results = [];
  for (const flow of flows) {
    for (const item of cases[flow]) {
      if (args.only && item.id !== args.only) continue;
      const caseId = `${item.id}-${Date.now()}`;
      const data = flow === 'chatbot' ? { case_id: caseId, message: item.message } : { case_id: caseId, question: item.question };
      const run = await make('POST', `/scenarios/${state[flow]}/run`, { data, responsive: true });
      const record = await logRecord(state, caseId) ?? {};
      const problems = [];
      if (run.status !== 1 && run.status !== '1') problems.push(`execution status ${run.status}`);
      if (item.expect === 'allow') {
        if (record.status !== 'llm_called') problems.push(`expected llm_called, got ${record.status ?? 'no record'}`);
        if (flow === 'chatbot' && record.llm_input !== item.message) problems.push('LLM input differs from the chat message');
        if (flow === 'rag' && !String(record.llm_input ?? '').includes(item.question)) problems.push('LLM input does not contain the question');
      } else {
        if (record.status !== 'rejected') problems.push(`expected rejected, got ${record.status ?? 'no record'}`);
        if (record.llm_input) problems.push('LLM step received text for a rejected input');
      }
      if (flow === 'rag' && item.expect_document && !String(record.retrieved ?? '').includes(`[${item.expect_document}]`)) {
        problems.push(`retrieval missed ${item.expect_document}`);
      }
      const out = { status: record.status };
      results.push({ flow, id: item.id, expect: item.expect, status: out.status ?? null, execution: run.executionId, pass: !problems.length, problems });
      console.log(`${problems.length ? 'FAIL' : 'PASS'}  ${flow.padEnd(7)} ${item.id.padEnd(22)} expect=${item.expect.padEnd(6)} got=${String(out.status).padEnd(9)} execution=${run.executionId}${problems.length ? `  -> ${problems.join('; ')}` : ''}`);
    }
  }
  const failed = results.filter(result => !result.pass).length;
  console.log(`\n${results.length - failed}/${results.length} cases passed`);
  if (args.report) await writeFile(args.report, `${JSON.stringify({ at: new Date().toISOString(), zone, results }, null, 2)}\n`);
  process.exitCode = failed ? 1 : 0;
}

if (positionals[0] === 'deploy') await deploy();
else if (positionals[0] === 'verify') await verify();
else { console.error('usage: run.mjs deploy --connection <id> | verify'); process.exitCode = 2; }
