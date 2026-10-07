import { Patronus, PatronusError } from '../../../sdk/typescript/src/index.js';
import { GuardRejected } from './guard.js';

export const API_BASE_URL = 'https://control.patronus.studio/api/v1';
export const AUTH_PROBE_JOB = 'job_00000000000000000000000000000000';
export type ScanKind = 'text' | 'url' | 'mcp';

// Bundle the existing SDK into each native package; runtime needs no CLI or SDK registry install.
export function client(apiKey: string, fetcher?: typeof fetch): Patronus {
  return new Patronus({ apiKey, timeoutMs: 10_000, fetch: fetcher });
}

export function scanBody(kind: ScanKind, content: string): Record<string, string> {
  if (typeof content !== 'string' || !content.trim()) throw new Error('Scan content is required.');
  if (kind === 'text') return { text: content };
  if (kind !== 'url' && kind !== 'mcp') throw new Error('Unsupported scan type.');
  const url = new URL(content);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Provide a public HTTPS URL without credentials.');
  return kind === 'url' ? { url: content } : { mcp_server_url: content };
}

// There is no account/test endpoint. A read of a missing job verifies scan:read without a billable scan.
// This deliberately does not claim to validate scan:write; POST enforces that scope.
export async function validateCredentials(apiKey: string, fetcher?: typeof fetch): Promise<void> {
  try { await client(apiKey, fetcher).getJob(AUTH_PROBE_JOB); }
  catch (error) {
    if (error instanceof PatronusError && error.status === 404) return;
    throw error;
  }
}

export function errorMessage(error: unknown): string {
  if (error instanceof GuardRejected) return error.message;
  if (error instanceof PatronusError) {
    return `Patronus ${error.kind} error${error.status ? ` (HTTP ${error.status})` : ''}` +
      `${error.code ? `; code=${error.code.replace(/[^A-Z0-9_]/gi, '').slice(0, 64)}` : ''}` +
      `${error.requestId ? `; request_id=${error.requestId.replace(/[^A-Z0-9_-]/gi, '').slice(0, 128)}` : ''}` +
      `${error.retryAfter !== undefined ? `; retry after ${error.retryAfter}s` : ''}.`;
  }
  return 'Patronus request failed. Check the input and connection.';
}

export { PatronusError };
