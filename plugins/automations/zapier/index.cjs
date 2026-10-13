const { client, scanBody, validateCredentials, errorMessage } = require('../shared/client.ts');
const { guardInput } = require('../shared/guard.ts');

const nativeFetch = z => async (url, init) => {
  const response = await z.request({
    url: String(url), method: init?.method || 'GET',
    headers: Object.fromEntries(new Headers(init?.headers).entries()),
    body: init?.body, redirect: 'manual', timeout: 10000,
    skipThrowForStatus: true, throwForThrottlingEarly: false,
  });
  return new Response(response.content, { status: response.status, headers: response.headers });
};

async function perform(z, bundle, operation) {
  try { return await operation(client(bundle.authData.api_key, nativeFetch(z))); }
  catch (error) { throw new z.errors.Error(errorMessage(error), 'PatronusApiError'); }
}

const sampleJob = { job_id: 'job_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', status: 'running', categories: {} };
module.exports = {
  version: '0.1.1', platformVersion: require('zapier-platform-core').version,
  authentication: {
    type: 'custom',
    fields: [{ key: 'api_key', label: 'API Key', type: 'password', required: true,
      helpText: 'Patronus account API key with scan:write and scan:read scopes.' }],
    test: async (z, bundle) => {
      try { await validateCredentials(bundle.authData.api_key, nativeFetch(z)); return { authenticated: true }; }
      catch (error) { throw new z.errors.Error(errorMessage(error), 'PatronusAuthenticationError'); }
    },
    connectionLabel: 'Patronus API',
  },
  creates: {
    guard_input: {
      key: 'guard_input', noun: 'Protected Input',
      display: { label: 'Guard Input', description: 'Pass RAG or prompt text through Patronus before your LLM. Releases text only after full approval.' },
      operation: {
        inputFields: [{ key: 'content', label: 'RAG / LLM Input', type: 'text', required: true }],
        perform: (z, bundle) => perform(z, bundle, async api => {
          const result = await guardInput(api, bundle.inputData.content);
          return { id: result.patronus.job_ids[0], ...result };
        }),
        sample: { id: sampleJob.job_id, text: 'Example approved input', patronus: { status: 'allowed', job_ids: [sampleJob.job_id] } },
        outputFields: [{ key: 'text', label: 'Protected Text', type: 'string' }, { key: 'patronus__status', label: 'Guard Status' }],
      },
    },
    submit_scan: {
      key: 'submit_scan', noun: 'Scan',
      display: { label: 'Submit Scan', description: 'Submit text, a public HTTPS page or public MCP metadata for injection and DLP scanning.' },
      operation: {
        inputFields: [
          { key: 'kind', label: 'Scan Type', required: true, choices: { text: 'Text', url: 'Public HTTPS URL', mcp: 'Public MCP Server' }, default: 'text' },
          { key: 'content', label: 'Content', type: 'text', required: true },
        ],
        perform: (z, bundle) => perform(z, bundle, async api => {
          const result = await api.submit(scanBody(bundle.inputData.kind, bundle.inputData.content));
          if (!result.jobs?.[0]?.job_id) throw new Error('Missing job identifier.');
          return { id: result.jobs[0].job_id, ...result };
        }),
        sample: { id: sampleJob.job_id, status: 'accepted', jobs: [sampleJob] },
        outputFields: [{ key: 'id', label: 'Job ID' }, { key: 'status', label: 'Submission Status' }, { key: 'jobs[]job_id', label: 'Job IDs' }],
      },
    },
    get_scan: {
      key: 'get_scan', noun: 'Scan Result',
      display: { label: 'Get Scan Result', description: 'Read a scan job. Check its status and findings before continuing.' },
      operation: {
        inputFields: [{ key: 'job_id', label: 'Job ID', required: true, helpText: 'Map the ID returned by Submit Scan.' }],
        perform: (z, bundle) => perform(z, bundle, async api => {
          const job = await api.getJob(bundle.inputData.job_id);
          return { id: job.job_id, ...job };
        }),
        sample: { id: sampleJob.job_id, ...sampleJob },
        outputFields: [{ key: 'job_id', label: 'Job ID' }, { key: 'status', label: 'Job Status' }, { key: 'decision', label: 'Decision' }, { key: 'safety_status', label: 'Safety Status' }],
      },
    },
  },
};
