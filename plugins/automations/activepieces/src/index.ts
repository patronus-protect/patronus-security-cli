import { createAction, createPiece, PieceAuth, Property } from '@activepieces/pieces-framework';
import { client, errorMessage, scanBody, validateCredentials } from '../../shared/client.js';
import type { ScanKind } from '../../shared/client.js';
import { guardInput } from '../../shared/guard.js';

const patronusAuth = PieceAuth.SecretText({
  displayName: 'Patronus API Key', required: true,
  description: 'Account API key with scan:write and scan:read scopes. Content is sent to the Patronus API.',
  validate: async ({ auth }) => {
    try { await validateCredentials(auth); return { valid: true }; }
    catch (error) { return { valid: false, error: errorMessage(error) }; }
  },
});

const submitScan = createAction({
  name: 'submit_scan', displayName: 'Submit Scan', auth: patronusAuth,
  description: 'Submit text, a public HTTPS page or public MCP metadata for injection and DLP scanning.',
  props: {
    kind: Property.StaticDropdown({ displayName: 'Scan Type', required: true, defaultValue: 'text', options: { options: [
      { label: 'Text', value: 'text' }, { label: 'Public HTTPS URL', value: 'url' }, { label: 'Public MCP Server', value: 'mcp' },
    ] } }),
    content: Property.LongText({ displayName: 'Content', required: true }),
  },
  async run(context) {
    try { return await client(context.auth.secret_text).submit(scanBody(context.propsValue.kind as ScanKind, context.propsValue.content)); }
    catch (error) { throw new Error(errorMessage(error)); }
  },
});

const getScan = createAction({
  name: 'get_scan', displayName: 'Get Scan Result', auth: patronusAuth,
  description: 'Read a scan job. Running and failed results are not clean verdicts.',
  props: { jobId: Property.ShortText({ displayName: 'Job ID', required: true }) },
  async run(context) {
    try { return await client(context.auth.secret_text).getJob(context.propsValue.jobId); }
    catch (error) { throw new Error(errorMessage(error)); }
  },
});

const guard = createAction({
  name: 'guard_input', displayName: 'Guard Input', auth: patronusAuth,
  description: 'Connect RAG or prompt text here before an LLM. Only fully verified allowed text is returned.',
  props: { content: Property.LongText({ displayName: 'RAG / LLM Input', required: true }) },
  async run(context) {
    try { return await guardInput(client(context.auth.secret_text), context.propsValue.content); }
    catch (error) { throw new Error(errorMessage(error)); }
  },
});

export const patronus = createPiece({
  displayName: 'Patronus', description: 'Patronus API security scans for automation flows',
  auth: patronusAuth, minimumSupportedRelease: '0.95.1',
  logoUrl: 'https://raw.githubusercontent.com/patronus-protect/patronus-security-cli/main/plugins/codex/assets/icon.png',
  authors: ['patronus-protect'], actions: [submitScan, getScan, guard], triggers: [],
});
