#!/usr/bin/env node
// Deterministic local scanner-protocol peer for the host-timeout acceptance test.
// Request checks finish immediately; response checks stay pending long enough for
// Claude to time out the production PostToolUse process.
import { randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';

const jobs = new Map();
const coverage = { complete: true, fields_total: 1, fields_scanned: 1, bytes_total: 1, bytes_scanned: 1 };
const reply = (id, result) => process.stdout.write(JSON.stringify({ id, result }) + '\n');

if (process.argv[2] === 'config') {
  process.stdout.write(JSON.stringify({ schema_version: 1, provider: { mode: 'local' },
    ark: { max_level: 'l1', categories: ['prompt_injection'], download_files: false },
    scan: {}, ignore: {}, chunking: {}, progress: {}, output: {}, support: {}, runtime: {} }));
} else for await (const line of createInterface({ input: process.stdin })) {
  const { id, method, params = {} } = JSON.parse(line);
  if (method === 'hello') {
    reply(id, { protocol_version: 1, provider: 'local', scanner_version: '0.1.0', ark_version: '0.1.8', ready: true,
      runtime: { response_wait_ms: 5000, request_timeout_ms: 1000, scan_timeout_ms: 60000, max_payload_bytes: 10 * 1024 * 1024 } });
  } else if (method === 'submit') {
    const scan_id = randomBytes(16).toString('hex');
    jobs.set(scan_id, { ...params, readyAt: Date.now() + (params.direction === 'response' ? 5000 : 0) });
    reply(id, { scan_id, status: 'pending' });
  } else {
    const job = jobs.get(params.scan_id);
    if (!job || params.session !== job.session) reply(id, { scan_id: params.scan_id, status: 'unavailable' });
    else if (method === 'cancel') reply(id, { scan_id: params.scan_id, status: 'cancelled' });
    else if (method === 'read_redacted') reply(id, { scan_id: params.scan_id, status: 'unavailable' });
    else if (Date.now() < job.readyAt) reply(id, { scan_id: params.scan_id, status: 'pending' });
    else reply(id, { scan_id: params.scan_id, status: 'approved', coverage, job_status: 'completed',
      ...(job.direction === 'response' ? { result: job.payload } : {}) });
  }
}
