const test = require('node:test');
const assert = require('node:assert/strict');

test('Make installer dry run assembles all five modules with native schema and no network or secrets', async () => {
  const { installMake } = await import('../make/install.mjs');
  const result = await installMake({ appName: 'patronus-test', token: 'private-token', fetcher: () => { throw Error('Network must not run'); } });
  assert.equal(result.applied, false);
  assert.equal(result.calls.length, 26);
  assert.ok(result.calls.some(call => call.path.endsWith('/1/icon') && Buffer.isBuffer(call.body)));
  assert.equal(result.calls[0].body.public, false);
  assert.ok(result.calls.filter(call => call.method === 'PUT').every(call => !/_/.test(call.path.split('/modules/')[1] ?? '')));
  const modules = result.calls.filter(call => call.path.endsWith('/modules'));
  assert.equal(modules.length, 5);
  assert.ok(modules.every(call => call.body.typeId === 4 && call.body.moduleInitMode === 'blank' && call.body.connection === 'patronus-test-connection'));
  assert.ok(!JSON.stringify(result).includes('private-token'));
});

test('Make installer binds the returned connection name and halts on API errors without disclosing secrets', async () => {
  const { installMake } = await import('../make/install.mjs');
  const calls = [];
  const result = await installMake({ appName: 'patronus-test', apply: true, token: 'private-token', fetcher: async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/sdk/apps')) return Response.json({ app: { name: 'patronus-test-x1y2z3' } });
    return Response.json({ appConnection: { name: 'generated-connection' } });
  } });
  // Make appends a suffix to private app names; every later call must use the returned name.
  assert.equal(result.appName, 'patronus-test-x1y2z3');
  assert.ok(result.calls.slice(1).every(call => call.path.includes('/patronus-test-x1y2z3') || call.path.startsWith('/sdk/apps/connections/')));
  assert.ok(result.calls.filter(call => call.path.endsWith('/modules')).every(call => call.body.connection === 'generated-connection'));
  assert.ok(calls.every(call => call.options.redirect === 'error' && call.options.headers.Authorization === 'Token private-token'));
  await assert.rejects(() => installMake({ apply: true, token: 'private-token', fetcher: async () => Response.json({ error: 'private-token' }, { status: 403 }) }), error => error.message.includes('HTTP 403') && !error.message.includes('private-token'));
  await assert.rejects(() => installMake({ apply: true, token: 'private-token', zone: 'attacker.example' }));
});
