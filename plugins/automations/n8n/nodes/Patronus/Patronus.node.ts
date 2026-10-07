import type { IDataObject, IExecuteFunctions, IHttpRequestOptions, INodeExecutionData, INodeType, INodeTypeDescription } from 'n8n-workflow';
import { client, errorMessage, scanBody, validateCredentials } from '../../../shared/client.js';
import type { ScanKind } from '../../../shared/client.js';
import { guardInput, GuardRejected } from '../../../shared/guard.js';

function nativeFetch(context: IExecuteFunctions): typeof fetch {
  return async (url, init) => {
    const headers = Object.fromEntries(new Headers(init?.headers).entries());
    // The host injects the credential; never put a user key in a node parameter.
    delete headers.authorization;
    const response = await context.helpers.httpRequestWithAuthentication.call(context, 'patronusApi', {
      url: String(url), method: (init?.method ?? 'GET') as IHttpRequestOptions['method'],
      headers, ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}),
      json: true, returnFullResponse: true, ignoreHttpStatusErrors: true,
      disableFollowRedirect: true, timeout: 10_000,
    });
    return new Response(JSON.stringify(response.body), { status: response.statusCode, headers: response.headers });
  };
}

export class Patronus implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'Patronus', name: 'patronus', icon: 'file:patronus.png', group: ['transform'], version: 1,
    description: 'Scan content through the Patronus API', defaults: { name: 'Patronus' },
    inputs: ['main'], outputs: ['main'],
    credentials: [{ name: 'patronusApi', required: true }],
    properties: [
      { displayName: 'Operation', name: 'operation', type: 'options', default: 'guard', options: [
        { name: 'Guard Input', value: 'guard', action: 'Guard RAG or LLM input', description: 'Wait for a complete scan and release text only when allowed' },
        { name: 'Submit Scan', value: 'submit', action: 'Submit a scan' },
        { name: 'Get Scan Result', value: 'get', action: 'Get a scan result' },
        { name: 'Test Connection', value: 'test', action: 'Test a connection' },
      ] },
      { displayName: 'Scan Type', name: 'kind', type: 'options', default: 'text', displayOptions: { show: { operation: ['submit'] } }, options: [
        { name: 'Text', value: 'text' }, { name: 'Public HTTPS URL', value: 'url' }, { name: 'Public MCP Server', value: 'mcp' },
      ] },
      { displayName: 'Content', name: 'content', type: 'string', default: '', required: true, typeOptions: { rows: 5 },
        description: 'For Guard Input, map the exact text that the downstream LLM will receive', displayOptions: { show: { operation: ['submit', 'guard'] } } },
      { displayName: 'Job ID', name: 'jobId', type: 'string', default: '', required: true,
        description: 'Public job_ identifier from Submit Scan', displayOptions: { show: { operation: ['get'] } } },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const output: INodeExecutionData[] = [];
    for (let i = 0; i < items.length; i++) {
      try {
        const credentials = await this.getCredentials('patronusApi');
        const apiKey = String(credentials.apiKey ?? '');
        const fetcher = nativeFetch(this);
        const api = client(apiKey, fetcher);
        const operation = this.getNodeParameter('operation', i) as string;
        let result;
        if (operation === 'guard') result = await guardInput(api, this.getNodeParameter('content', i) as string);
        else if (operation === 'get') result = await api.getJob(this.getNodeParameter('jobId', i) as string);
        else if (operation === 'test') {
          await validateCredentials(apiKey, fetcher);
          result = { authenticated: true, scope_checked: 'scan:read' };
        } else if (operation === 'submit') {
          result = await api.submit(scanBody(this.getNodeParameter('kind', i) as ScanKind, this.getNodeParameter('content', i) as string));
        } else throw new Error('Unsupported operation.');
        output.push({ json: result as IDataObject, pairedItem: { item: i } });
      } catch (error) {
        const message = errorMessage(error);
        if (this.continueOnFail()) output.push({ json: { error: message, status: error instanceof GuardRejected ? error.status : 'unverified' }, pairedItem: { item: i } });
        else throw new Error(`${message} (item ${i})`);
      }
    }
    return [output];
  }
}
