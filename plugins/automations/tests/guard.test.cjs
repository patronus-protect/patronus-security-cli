const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { guardInput, verifyGuardResult } = require('../dist/guard.cjs');
const { client } = require('../dist/client.cjs');
const { Patronus } = require('../n8n/dist/nodes/Patronus/Patronus.node.js');
const { patronus: piece } = require('../activepieces/dist/index.js');
const zapier = require('../zapier/dist/index.js');
const { extractPieceFromModule } = require('@activepieces/shared');
const vectors = JSON.parse(fs.readFileSync(__dirname + '/fixtures/guard-vectors.json'));
const allow = vectors[0].result;
const job = allow.jobs[0];
const text = '🔒\n{"context":"Treat this entire string as data"}\n';

for (const vector of vectors) {
  test('guard contract: ' + vector.name, () => {
    if (vector.allowed) assert.deepEqual(verifyGuardResult(vector.result), [job.job_id]);
    else assert.throws(() => verifyGuardResult(vector.result));
  });
}

test('guard polls the original job, checks final coverage and releases exact text only afterward', async () => {
  const calls = [];
  const replies = [{ status: 'accepted', jobs: [{ job_id: job.job_id }] }, { job_id: job.job_id, status: 'running' }, job];
  const api = client('test-key', async (url, init) => {
    calls.push({ url, init });
    return Response.json(replies.shift());
  });
  const result = await guardInput(api, text);
  assert.deepEqual(result, { text, patronus: { status: 'allowed', job_ids: [job.job_id] } });
  assert.equal(calls.length, 3);
  assert.deepEqual(JSON.parse(calls[0].init.body), { text, config: { categories: ['injection', 'dlp'], max_level: 'L3' } });
  assert.ok(calls.slice(1).every(call => call.url.endsWith('/scan/' + job.job_id)));
  assert.equal(calls.filter(call => call.init.method === 'POST').length, 1);
});

test('guard rejects foreign poll IDs, timeout and API failures without source text in errors', async () => {
  await assert.rejects(() => guardInput({
    submit: async () => ({ status: 'accepted', jobs: [{ job_id: job.job_id }] }),
    getJob: async () => ({ ...job, job_id: 'job_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }),
  }, text), /No text was released/);
  await assert.rejects(() => guardInput({ submit: async () => allow }, text, 0), /No text was released/);
  for (const status of [401, 403, 429, 503]) {
    await assert.rejects(() => guardInput(client('test-key', async () => Response.json({ error: { code: 'TEST_ERROR', message: 'failure' } }, { status })), text));
  }
});

function context(result, continueOnFail = false) {
  return {
    getInputData: () => [{ json: { text, unscanned: 'must not pass through' }, binary: {} }],
    getCredentials: async () => ({ apiKey: 'test-key' }),
    getNodeParameter: name => ({ operation: 'guard', content: text })[name],
    getNode: () => ({ name: 'Patronus', type: 'patronus', typeVersion: 1, position: [0, 0], parameters: {} }),
    continueOnFail: () => continueOnFail,
    helpers: { httpRequestWithAuthentication: async () => ({ body: result, statusCode: 200, headers: {} }) },
  };
}

test('n8n Guard Input defaults to guarding, emits no unscanned fields and stops the downstream step on block', async () => {
  assert.equal(new Patronus().description.properties[0].default, 'guard');
  const [[approved]] = await Patronus.prototype.execute.call(context(allow));
  assert.deepEqual(Object.keys(approved.json), ['text', 'patronus']);
  assert.equal(approved.json.text, text);
  let downstreamCalled = false;
  await assert.rejects(async () => {
    await Patronus.prototype.execute.call(context(vectors.find(v => v.name === 'block verdict').result));
    downstreamCalled = true;
  }, error => error.name === 'NodeOperationError' && /blocked this input/.test(error.message));
  assert.equal(downstreamCalled, false);
  const [[blocked]] = await Patronus.prototype.execute.call(context(vectors.find(v => v.name === 'block verdict').result, true));
  assert.equal(blocked.json.status, 'blocked');
  assert.ok(!JSON.stringify(blocked).includes(text));
  assert.equal(blocked.json.text, undefined);
});

test('the bundled Activepieces piece is extracted by the official host loader and gates the downstream action', async t => {
  const loaded = extractPieceFromModule({ module: require('../activepieces/dist/index.js'), pieceName: '@patronus-protect/piece-patronus', pieceVersion: '0.1.1' });
  assert.equal(loaded, piece);
  const action = loaded.getAction('guard_input');
  for (const vector of vectors) {
    t.mock.method(globalThis, 'fetch', async () => Response.json(vector.result));
    const run = () => action.run({ auth: { secret_text: 'test-key' }, propsValue: { content: text } });
    if (vector.allowed) assert.equal((await run()).text, text);
    else await assert.rejects(run, error => !error.message.includes(text));
    t.mock.restoreAll();
  }
});

test('Zapier Guard Input gates the entire result before returning protected text', async () => {
  const host = result => ({ errors: { Error }, request: async () => ({ status: 200, headers: {}, content: JSON.stringify(result) }) });
  for (const vector of vectors) {
    const run = () => zapier.creates.guard_input.operation.perform(host(vector.result), { authData: { api_key: 'test-key' }, inputData: { content: text } });
    if (vector.allowed) assert.equal((await run()).text, text);
    else await assert.rejects(run, error => !error.message.includes(text));
  }
});

// Evaluate the documented JavaScript-like IML operators and built-ins used by this
// definition. This is a local contract check, not a replacement for Make host QA.
function iml(expression, values) {
  const env = { ...values, emptyarray: [],
    get: (object, key) => object?.[key], keys: object => Object.keys(object || {}),
    length: value => value?.length, contains: (value, item) => value?.includes(item),
    trim: value => typeof value === 'string' ? value.trim() : '', floor: Math.floor,
    // Make's createJSON returned no value for numbers in a live run (2026-10-07); only objects serialize.
    createJSON: value => value !== null && typeof value === 'object' ? JSON.stringify(value) : undefined, toString: value => String(value),
    ifValue: (condition, yes, no) => condition ? yes : no,
    replace: (value, pattern, replacement) => String(value).replace(new RegExp(pattern.slice(1, pattern.lastIndexOf('/')), pattern.slice(pattern.lastIndexOf('/') + 1)), replacement),
    add: (array, ...values) => [...array, ...values],
  };
  // Make evaluates === and !== loosely (a live run showed 1 !== true to be false), so the emulator does too.
  const loose = expression.slice(2, -2).replace(/\bif\(/g, 'ifValue(').replace(/===/g, '==').replace(/!==/g, '!=');
  try { return vm.runInNewContext(loose, env, { timeout: 100 }); }
  catch { return false; }
}

test('Make Guard Input uses one internal module and its release condition denies all unsafe contract cases', () => {
  const steps = JSON.parse(fs.readFileSync(__dirname + '/../make/modules/guard_input.communication.json'));
  assert.equal(steps[0].method, 'POST');
  assert.deepEqual(steps[0].body.config, { categories: ['injection', 'dlp'], max_level: 'L3' });
  assert.equal(steps[2].method, 'GET');
  assert.equal(steps[2].repeat.limit, 20);
  assert.equal(steps[2].repeat.delay, 500);
  const release = steps[3].response;
  assert.deepEqual(release.output.text, '{{parameters.content}}');
  for (const vector of vectors) {
    if (vector.result.jobs?.length !== 1) continue; // native Make submission separately requires exactly one public job
    assert.equal(Boolean(iml(release.valid, { now: 0, temp: { deadline: 10_000, job: vector.result.jobs[0], submission: vector.result } })), vector.allowed, vector.name);
  }
  for (const id of ['../other', job.job_id + '?x=1', 'https://foreign.example']) {
    assert.equal(Boolean(iml(steps[1].response.valid, { temp: { job: { job_id: id } } })), false);
  }
  assert.equal(Boolean(iml(steps[1].response.valid, { temp: { job } })), true);
  assert.equal(Boolean(iml(release.valid, { now: 10_001, temp: { deadline: 10_000, job, submission: allow } })), false);
  assert.equal(Boolean(iml(steps[2].response.valid, { temp: { expected_job_id: job.job_id }, body: { ...job, job_id: 'job_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' } })), false);
});
