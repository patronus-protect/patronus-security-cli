import type { ScanResponse } from '../../../sdk/typescript/src/index.js';
import { Patronus } from '../../../sdk/typescript/src/index.js';

import { evaluateGuardResult, GUARD_CONFIG, JOB_ID } from './guard-policy.js';

export { GUARD_CONFIG };

export class GuardRejected extends Error {
  constructor(readonly status: 'blocked' | 'unverified') {
    super(status === 'blocked' ? 'Patronus blocked this input. No text was released.' : 'Patronus could not verify this input. No text was released.');
    this.name = 'GuardRejected';
  }
}

export function verifyGuardResult(value: unknown): string[] {
  const verdict = evaluateGuardResult(value);
  if (verdict.status !== 'allowed') throw new GuardRejected(verdict.status);
  return verdict.jobIds;
}

export async function guardInput(api: Patronus, text: string, timeoutMs = 10_000) {
  if (typeof text !== 'string' || !text.trim()) throw new GuardRejected('unverified');
  const deadline = Date.now() + timeoutMs;
  const checkDeadline = () => { if (Date.now() >= deadline) throw new GuardRejected('unverified'); };
  let result: ScanResponse = await api.submit({ text, config: GUARD_CONFIG });
  checkDeadline();
  if (result.status === 'accepted') {
    if (!Array.isArray(result.jobs) || !result.jobs.length || result.jobs.length > 32 ||
        result.jobs.some(job => typeof job.job_id !== 'string' || !JOB_ID.test(job.job_id)) ||
        new Set(result.jobs.map(job => job.job_id)).size !== result.jobs.length) throw new GuardRejected('unverified');
    const jobs = [];
    for (const accepted of result.jobs) {
      let delay = 250;
      while (true) {
        checkDeadline();
        const job = await api.getJob(accepted.job_id);
        checkDeadline();
        if (job.job_id !== accepted.job_id) throw new GuardRejected('unverified');
        if (job.status === 'queued' || job.status === 'running') {
          await new Promise(resolve => setTimeout(resolve, Math.min(delay, deadline - Date.now())));
          delay = Math.min(delay * 2, 1000);
        } else { jobs.push(job); break; }
      }
    }
    result = { ...result, status: 'completed', jobs };
  }
  const jobIds = verifyGuardResult(result);
  return { text, patronus: { status: 'allowed' as const, job_ids: jobIds } };
}
