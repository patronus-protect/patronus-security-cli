const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { client, scanBody, validateCredentials, errorMessage, AUTH_PROBE_JOB, API_BASE_URL } = require('../dist/client.cjs');
const { Patronus } = require('../n8n/dist/nodes/Patronus/Patronus.node.js');
const { PatronusApi } = require('../n8n/dist/credentials/PatronusApi.credentials.js');
const { patronus: piece } = require('../activepieces/dist/index.js');
// Obtain actions from the native piece registry, as the installed host does.
const ap = { patronus: piece, patronusAuth: piece.auth, submitScan: piece._actions.submit_scan, getScan: piece._actions.get_scan };
const zapier = require('../zapier/dist/index.js');
const { validateAppDefinition } = require('zapier-platform-schema');
const { serializeApp } = require('zapier-platform-core/src/tools/schema');
const fixture = name => JSON.parse(fs.readFileSync(path.join(__dirname, '../../../contract/fixtures', name + '.json')));
const flat = fixture('completed-flat');
const attack = fixture('completed-injection');
const accepted = { status: 'accepted', jobs: [{ job_id: flat.job_id }] };
const key = 'automation-test-credential';
const requestError = status => ({ error: { code: 'TEST_ERROR', message: key, request_id: 'req_test' } });

test('reuses the API contract, preserves raw JSON-looking text and does not poll submissions', async () => {
  const calls = [];
  const api = client(key, async (url, init) => {
    calls.push({ url, init });
    return Response.json(accepted, { status: 202 });
  });
  assert.deepEqual(await api.submit(scanBody('text', '{"text":"raw input"}')), accepted);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, API_BASE_URL + '/scan');
  assert.equal(calls[0].init.headers.Authorization, 'Bearer ' + key);
  assert.equal(calls[0].init.redirect, 'error');
  assert.deepEqual(JSON.parse(calls[0].init.body), { text: '{"text":"raw input"}' });
});

test('normalizes flat completions, preserves block decisions and exposes running jobs unchanged', async () => {
  assert.equal((await client(key, async () => Response.json(flat)).submit({ text: 'hello' })).jobs[0].decision, 'allow');
  assert.deepEqual(await client(key, async () => Response.json(attack)).submit({ text: 'test' }), attack);
  const running = { job_id: flat.job_id, status: 'running' };
  assert.deepEqual(await client(key, async () => Response.json(running)).getJob(flat.job_id), running);
});

test('validates job identifiers and input before credentials can be sent to another path', async () => {
  let calls = 0;
  const api = client(key, async () => { calls++; return Response.json(flat); });
  for (const id of ['../other', 'https://foreign.example', flat.job_id + '?key=x', '']) {
    await assert.rejects(() => api.getJob(id));
  }
  assert.equal(calls, 0);
  for (const [kind, content] of [['text', '  '], ['url', 'http://example.com'], ['mcp', 'https://user:pass@example.com'], ['unknown', 'hello']]) {
    assert.throws(() => scanBody(kind, content));
  }
  assert.deepEqual(scanBody('url', 'https://example.com/page'), { url: 'https://example.com/page' });
  assert.deepEqual(scanBody('mcp', 'https://example.com/mcp'), { mcp_server_url: 'https://example.com/mcp' });
});

test('connection test is read-only, accepts authenticated 404, rejects unavailable or unauthorized responses', async () => {
  for (const status of [200, 404, 401, 403, 429, 503]) {
    const calls = [];
    const fetcher = async (url, init) => { calls.push({ url, init }); return Response.json(status === 200 ? flat : requestError(status), { status }); };
    if ([200, 404].includes(status)) await validateCredentials(key, fetcher);
    else await assert.rejects(() => validateCredentials(key, fetcher));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, API_BASE_URL + '/scan/' + AUTH_PROBE_JOB);
    assert.equal(calls[0].init.method, undefined);
    assert.equal(calls[0].init.body, undefined);
  }
});

test('API errors do not disclose the credential or server-provided error text, and retain retry metadata', async () => {
  for (const status of [401, 403, 404, 429, 500]) {
    try {
      await client(key, async () => Response.json(requestError(status), { status, headers: { 'Retry-After': '7' } })).submit({ text: 'test' });
      assert.fail('Expected API error');
    } catch (error) {
      const message = errorMessage(error);
      assert.ok(!message.includes(key));
      assert.match(message, new RegExp('HTTP ' + status));
      assert.match(message, /retry after 7s/);
    }
  }
  assert.ok(!errorMessage(new Error(key)).includes(key));
});

function n8nContext(parameters, replies, continueOnFail = false) {
  const calls = [];
  return {
    calls,
    getInputData: () => parameters.map(() => ({ json: {} })),
    getCredentials: async () => ({ apiKey: key }),
    getNodeParameter: (name, i) => parameters[i][name],
    getNode: () => ({ name: 'Patronus', type: 'patronus', typeVersion: 1, position: [0, 0], parameters: {} }),
    continueOnFail: () => continueOnFail,
    helpers: { httpRequestWithAuthentication: async function (credential, options) {
      calls.push({ credential, options, context: this });
      const reply = replies.shift();
      return { body: reply.body, statusCode: reply.status || 200, headers: {} };
    } },
  };
}

test('n8n invokes native credential transport for each item and keeps item linkage', async () => {
  const context = n8nContext([{ operation: 'submit', kind: 'text', content: 'first' }, { operation: 'get', jobId: flat.job_id }], [{ body: accepted, status: 202 }, { body: flat }]);
  const [items] = await Patronus.prototype.execute.call(context);
  assert.deepEqual(items.map(item => item.pairedItem), [{ item: 0 }, { item: 1 }]);
  assert.deepEqual(items[0].json, accepted);
  assert.equal(items[1].json.decision, 'allow');
  assert.equal(context.calls[0].credential, 'patronusApi');
  assert.equal(context.calls[0].context, context);
  assert.equal(context.calls[0].options.headers.authorization, undefined);
  assert.equal(context.calls[0].options.disableFollowRedirect, true);
  assert.deepEqual(context.calls[0].options.body, { text: 'first' });
  assert.equal(new PatronusApi().properties[0].typeOptions.password, true);
  assert.match(new PatronusApi().authenticate.properties.headers.Authorization, /credentials.apiKey/);
});

test('n8n continue-on-fail explicitly marks errors unverified', async () => {
  const context = n8nContext([{ operation: 'submit', kind: 'text', content: 'hello' }], [{ body: requestError(401), status: 401 }], true);
  const [[item]] = await Patronus.prototype.execute.call(context);
  assert.equal(item.json.status, 'unverified');
  assert.ok(!item.json.error.includes(key));
  const stop = n8nContext([{ operation: 'get', jobId: flat.job_id }], [{ body: requestError(401), status: 401 }]);
  await assert.rejects(() => Patronus.prototype.execute.call(stop), /HTTP 401/);
});

const z = replies => ({
  calls: [], errors: { Error },
  async request(options) {
    this.calls.push(options);
    const reply = replies.shift();
    return { status: reply.status || 200, content: JSON.stringify(reply.body), headers: {} };
  },
});

test('Zapier app satisfies official schema and actions use z.request without waiting for jobs', async () => {
  assert.deepEqual(validateAppDefinition(serializeApp(zapier)).errors, []);
  const host = z([{ body: accepted, status: 202 }, { body: flat }, { body: requestError(404), status: 404 }]);
  const result = await zapier.creates.submit_scan.operation.perform(host, { authData: { api_key: key }, inputData: { kind: 'text', content: 'hello' } });
  assert.equal(result.id, flat.job_id);
  assert.equal(result.status, 'accepted');
  assert.equal(host.calls.length, 1);
  assert.equal(host.calls[0].headers.authorization, 'Bearer ' + key);
  assert.equal(host.calls[0].redirect, 'manual');
  assert.equal((await zapier.creates.get_scan.operation.perform(host, { authData: { api_key: key }, inputData: { job_id: result.id } })).decision, 'allow');
  assert.deepEqual(await zapier.authentication.test(host, { authData: { api_key: key } }), { authenticated: true });
});

test('Zapier rejects auth and quota failures without returning an apparently successful scan', async () => {
  for (const status of [401, 403, 429, 503]) {
    const host = z([{ body: requestError(status), status }]);
    await assert.rejects(() => zapier.creates.submit_scan.operation.perform(host, { authData: { api_key: key }, inputData: { kind: 'text', content: 'hello' } }), error => {
      assert.ok(!error.message.includes(key));
      return error.message.includes('HTTP ' + status);
    });
  }
});

test('Activepieces registers native actions and uses the current secret-text auth shape', async t => {
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    calls.push({ url, init });
    return Response.json(String(url).endsWith(AUTH_PROBE_JOB) ? requestError(404) : String(url).endsWith(flat.job_id) ? flat : accepted,
      { status: String(url).endsWith(AUTH_PROBE_JOB) ? 404 : 200 });
  });
  const connection = { secret_text: key };
  assert.deepEqual(await ap.patronusAuth.validate({ auth: key }), { valid: true });
  assert.deepEqual(await ap.submitScan.run({ auth: connection, propsValue: { kind: 'mcp', content: 'https://example.com/mcp' } }), accepted);
  assert.equal((await ap.getScan.run({ auth: connection, propsValue: { jobId: flat.job_id } })).decision, 'allow');
  assert.equal(calls[1].init.headers.Authorization, 'Bearer ' + key);
  assert.deepEqual(JSON.parse(calls[1].init.body), { mcp_server_url: 'https://example.com/mcp' });
  assert.deepEqual(Object.keys(ap.patronus._actions), ['submit_scan', 'get_scan', 'guard_input']);
});

test('Make definitions inherit Bearer auth, mask logs and map all request types exactly', () => {
  const read = name => JSON.parse(fs.readFileSync(path.join(__dirname, '../make', name + '.json')));
  const base = read('base');
  assert.equal(base.headers.authorization, 'Bearer {{connection.apiKey}}');
  assert.ok(base.log.sanitize.includes('request.headers.authorization'));
  assert.ok(base.log.sanitize.includes('request.body'));
  assert.equal(read('connections/patronus.parameters')[0].type, 'password');
  // Make treats every non-2xx response as a failed check, so the check is a minimal L1 text scan.
  const check = read('connections/patronus.communication');
  assert.equal(check.method, 'POST');
  assert.deepEqual(check.body.config, { categories: ['injection'], max_level: 'L1' });
  assert.ok(check.log.sanitize.includes('request.headers.authorization'));
  for (const [module, field] of [['scan_text', 'text'], ['scan_url', 'url'], ['scan_mcp', 'mcp_server_url']]) {
    const action = read('modules/' + module + '.communication');
    assert.equal(action.url, '/scan');
    assert.equal(action.method, 'POST');
    assert.deepEqual(action.body, { [field]: '{{parameters.content}}' });
    assert.equal(action.response.output, '{{body}}');
  }
  const pattern = new RegExp(read('modules/get_scan.parameters')[0].validate.pattern);
  assert.ok(pattern.test(flat.job_id));
  assert.ok(!pattern.test('../account'));
});

test('Zapier package root exposes the app for the Zapier runtime', () => {
  // The Zapier Lambda wrapper requires /var/task/index.js regardless of package.json "main".
  const pkg = require('../zapier/package.json');
  assert.equal(pkg.main, 'index.js');
  assert.ok(pkg.files.includes('index.js'));
  assert.strictEqual(require('../zapier/index.js'), require('../zapier/dist/index.js'));
});
