import {
  NodeApiError,
  NodeConnectionTypes,
  NodeOperationError,
  sleep,
  type IDataObject,
  type IExecuteFunctions,
  type IHttpRequestMethods,
  type INodeExecutionData,
  type INodeType,
  type INodeTypeDescription,
  type JsonObject,
} from 'n8n-workflow';
import { evaluateGuardResult, GUARD_CONFIG, JOB_ID } from './lib/policy';

const API_BASE_URL = 'https://control.patronus.studio/api/v1';
const GUARD_TIMEOUT_MS = 10_000;
const REQUEST_TIMEOUT_MS = 10_000;
type ScanKind = 'text' | 'url' | 'mcp';
type Rejection = 'blocked' | 'unverified';

const REJECTION_MESSAGES: Record<Rejection, string> = {
  blocked: 'Patronus blocked this input. No text was released.',
  unverified: 'Patronus could not verify this input. No text was released.',
};

const asObject = (value: unknown): IDataObject => value && typeof value === 'object' && !Array.isArray(value) ? value as IDataObject : {};
const clean = (value: unknown, pattern: RegExp, length: number) => typeof value === 'string' ? value.replace(pattern, '').slice(0, length) : '';

// Server-provided messages can echo input; only sanitized identifiers reach the workflow.
function apiErrorMessage(status: number, body: unknown, retryAfter: unknown): string {
  const error = asObject(asObject(body).error);
  const code = clean(error.code, /[^A-Z0-9_]/gi, 64);
  const requestId = clean(error.request_id ?? asObject(body).request_id, /[^A-Z0-9_-]/gi, 128);
  const retry = Number(retryAfter);
  return `Patronus API error (HTTP ${status})${code ? `; code=${code}` : ''}${requestId ? `; request_id=${requestId}` : ''}` +
    `${Number.isFinite(retry) && retry >= 0 ? `; retry after ${retry}s` : ''}.`;
}

async function apiRequest(context: IExecuteFunctions, method: IHttpRequestMethods, path: string, body?: IDataObject): Promise<IDataObject> {
  let response;
  try {
    // The credential injects the Authorization header; a key never appears in node parameters.
    response = await context.helpers.httpRequestWithAuthentication.call(context, 'patronusApi', {
      url: `${API_BASE_URL}${path}`, method, headers: { Accept: 'application/json', ...(body ? { Prefer: 'wait=1' } : {}) },
      ...(body ? { body } : {}), json: true, returnFullResponse: true, ignoreHttpStatusErrors: true,
      disableFollowRedirect: true, timeout: REQUEST_TIMEOUT_MS,
    });
  } catch {
    throw new NodeApiError(context.getNode(), {} as JsonObject, { message: 'Patronus API request failed. Check the connection and try again.' });
  }
  const status = Number(response.statusCode);
  if (status < 200 || status >= 300) {
    const headers = asObject(response.headers);
    throw new NodeApiError(context.getNode(), {} as JsonObject, {
      message: apiErrorMessage(status, response.body, headers['retry-after']), httpCode: String(status),
    });
  }
  return asObject(response.body);
}

function scanBody(context: IExecuteFunctions, kind: ScanKind, content: string, itemIndex: number): IDataObject {
  if (typeof content !== 'string' || !content.trim()) throw new NodeOperationError(context.getNode(), 'Scan content is required.', { itemIndex });
  if (kind === 'text') return { text: content };
  let url: URL | undefined;
  try { url = new URL(content); } catch { url = undefined; }
  if (!url || url.protocol !== 'https:' || url.username || url.password) {
    throw new NodeOperationError(context.getNode(), 'Provide a public HTTPS URL without credentials.', { itemIndex });
  }
  return kind === 'url' ? { url: content } : { mcp_server_url: content };
}

// A flat completed job is returned as { job_id, status, ... }; the policy expects { status, jobs: [...] }.
function normalizeSubmission(value: IDataObject): IDataObject {
  if (Array.isArray(value.jobs) || typeof value.job_id !== 'string') return value;
  const job = { ...value };
  const response: IDataObject = { status: value.status === 'failed' ? 'failed' : 'completed', jobs: [job] };
  for (const field of ['input', 'extraction', 'coverage', 'usage', 'request_id']) {
    delete job[field];
    if (value[field] !== undefined) response[field] = value[field];
  }
  return response;
}

async function guard(context: IExecuteFunctions, text: string): Promise<{ status: 'allowed'; jobIds: string[] } | { status: Rejection }> {
  if (typeof text !== 'string' || !text.trim()) return { status: 'unverified' };
  const deadline = Date.now() + GUARD_TIMEOUT_MS;
  let result = normalizeSubmission(await apiRequest(context, 'POST', '/scan', { text, config: GUARD_CONFIG }));
  if (Date.now() >= deadline) return { status: 'unverified' };
  if (result.status === 'accepted') {
    const accepted = Array.isArray(result.jobs) ? result.jobs.map(asObject) : [];
    const ids = accepted.map(job => job.job_id);
    if (!ids.length || ids.length > 32 || ids.some(id => typeof id !== 'string' || !JOB_ID.test(id)) || new Set(ids).size !== ids.length) return { status: 'unverified' };
    const jobs: IDataObject[] = [];
    for (const id of ids as string[]) {
      let delay = 250;
      while (true) {
        if (Date.now() >= deadline) return { status: 'unverified' };
        const job = await apiRequest(context, 'GET', `/scan/${id}`);
        if (Date.now() >= deadline || job.job_id !== id) return { status: 'unverified' };
        if (job.status !== 'queued' && job.status !== 'running') { jobs.push(job); break; }
        await sleep(Math.min(delay, deadline - Date.now()));
        delay = Math.min(delay * 2, 1000);
      }
    }
    result = { ...result, status: 'completed', jobs };
  }
  return evaluateGuardResult(result);
}

export class Patronus implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'Patronus',
    name: 'patronus',
    icon: { light: 'file:patronus.svg', dark: 'file:patronus.dark.svg' },
    group: ['transform'],
    version: 1,
    subtitle: '={{ $parameter["operation"] }}',
    description: 'Guard RAG and LLM input against prompt injection and data leaks with Patronus',
    defaults: { name: 'Patronus' },
    usableAsTool: true,
    inputs: [NodeConnectionTypes.Main],
    outputs: [NodeConnectionTypes.Main],
    credentials: [{ name: 'patronusApi', required: true }],
    properties: [
      {
        displayName: 'Operation', name: 'operation', type: 'options', noDataExpression: true, default: 'guard',
        options: [
          { name: 'Guard Input', value: 'guard', action: 'Guard RAG or LLM input', description: 'Wait for a complete scan and release text only when allowed' },
          { name: 'Submit Scan', value: 'submit', action: 'Submit a scan', description: 'Submit text, a public HTTPS page or public MCP metadata' },
          { name: 'Get Scan Result', value: 'get', action: 'Get a scan result', description: 'Read a scan job and its findings' },
        ],
      },
      {
        displayName: 'Scan Type', name: 'kind', type: 'options', default: 'text', displayOptions: { show: { operation: ['submit'] } },
        options: [
          { name: 'Text', value: 'text' },
          { name: 'Public HTTPS URL', value: 'url' },
          { name: 'Public MCP Server', value: 'mcp' },
        ],
      },
      {
        displayName: 'Content', name: 'content', type: 'string', default: '', required: true, typeOptions: { rows: 5 },
        description: 'For Guard Input, map the exact text that the downstream LLM will receive',
        displayOptions: { show: { operation: ['submit', 'guard'] } },
      },
      {
        displayName: 'Job ID', name: 'jobId', type: 'string', default: '', required: true,
        description: 'Public job_ identifier from Submit Scan', displayOptions: { show: { operation: ['get'] } },
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const output: INodeExecutionData[] = [];
    for (let i = 0; i < items.length; i++) {
      try {
        const operation = this.getNodeParameter('operation', i) as string;
        if (operation === 'guard') {
          const text = this.getNodeParameter('content', i) as string;
          const verdict = await guard(this, text);
          if (verdict.status !== 'allowed') {
            const message = REJECTION_MESSAGES[verdict.status];
            if (this.continueOnFail()) { output.push({ json: { error: message, status: verdict.status }, pairedItem: { item: i } }); continue; }
            throw new NodeOperationError(this.getNode(), message, { itemIndex: i });
          }
          output.push({ json: { text, patronus: { status: 'allowed', job_ids: verdict.jobIds } }, pairedItem: { item: i } });
        } else if (operation === 'submit') {
          const body = scanBody(this, this.getNodeParameter('kind', i) as ScanKind, this.getNodeParameter('content', i) as string, i);
          output.push({ json: await apiRequest(this, 'POST', '/scan', body), pairedItem: { item: i } });
        } else if (operation === 'get') {
          const jobId = this.getNodeParameter('jobId', i) as string;
          if (typeof jobId !== 'string' || !JOB_ID.test(jobId)) throw new NodeOperationError(this.getNode(), 'Provide a public job_ identifier.', { itemIndex: i });
          output.push({ json: await apiRequest(this, 'GET', `/scan/${jobId}`), pairedItem: { item: i } });
        } else {
          throw new NodeOperationError(this.getNode(), 'Unsupported operation.', { itemIndex: i });
        }
      } catch (error) {
        if (this.continueOnFail()) {
          output.push({ json: { error: (error as Error).message, status: 'unverified' }, pairedItem: { item: i } });
          continue;
        }
        throw new NodeOperationError(this.getNode(), error as Error, { itemIndex: i });
      }
    }
    return [output];
  }
}
