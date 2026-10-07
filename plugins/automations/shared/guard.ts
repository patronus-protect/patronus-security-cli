import type { Json, ScanResponse } from '../../../sdk/typescript/src/index.js';
import { Patronus } from '../../../sdk/typescript/src/index.js';

export const GUARD_CONFIG = { categories: ['injection', 'dlp'], max_level: 'L3' };
const JOB_ID = /^job_[0-9a-f]{32}$/i;
type ObjectValue = Record<string, Json | undefined>;
const object = (value: unknown): ObjectValue => value && typeof value === 'object' && !Array.isArray(value) ? value as ObjectValue : {};

export class GuardRejected extends Error {
  constructor(readonly status: 'blocked' | 'unverified') {
    super(status === 'blocked' ? 'Patronus blocked this input. No text was released.' : 'Patronus could not verify this input. No text was released.');
    this.name = 'GuardRejected';
  }
}

function completeMetadata(value: unknown): boolean {
  const metadata = object(value);
  return metadata.state === 'complete' && typeof metadata.documents_total === 'number' && Number.isInteger(metadata.documents_total) && metadata.documents_total >= 1 &&
    metadata.documents_total === metadata.documents_scanned &&
    (metadata.pages_total === undefined && metadata.pages_scanned === undefined ||
      typeof metadata.pages_total === 'number' && Number.isInteger(metadata.pages_total) && metadata.pages_total >= 1 && metadata.pages_total === metadata.pages_scanned);
}

export function verifyGuardResult(value: unknown): string[] {
  const response = object(value);
  if (response.status !== 'completed' || !Array.isArray(response.jobs) || !response.jobs.length || response.jobs.length > 32) throw new GuardRejected('unverified');
  const ids: string[] = [];
  for (const value of response.jobs) {
    const job = object(value);
    if (typeof job.job_id !== 'string' || !JOB_ID.test(job.job_id) || ids.includes(job.job_id) || job.status !== 'completed') throw new GuardRejected('unverified');
    if (job.decision !== 'allow' || job.safety_status !== undefined && job.safety_status !== 'benign' ||
        response.decision !== undefined && response.decision !== 'allow' || response.safety_status !== undefined && response.safety_status !== 'benign') throw new GuardRejected('blocked');
    const completion = object(job.completion);
    if (!completeMetadata(job.coverage === undefined ? response.coverage : job.coverage) || !completeMetadata(job.extraction === undefined ? response.extraction : job.extraction) ||
        completion.state !== 'complete' || completion.failures !== undefined && (!Array.isArray(completion.failures) || completion.failures.length > 0)) throw new GuardRejected('unverified');
    const categories = object(job.categories);
    if (Object.keys(categories).length !== 2) throw new GuardRejected('unverified');
    for (const name of GUARD_CONFIG.categories) {
      const category = object(categories[name]);
      const final = Object.hasOwn(category, 'final_result');
      const result = final ? object(category.final_result) : category;
      if (result.class_name !== 'benign' && result.class_name !== 'safe') throw new GuardRejected(result.class_name ? 'blocked' : 'unverified');
      // Use the API's final classification without re-thresholding detector candidates.
      if (typeof result.confidence !== 'number' || !Number.isFinite(result.confidence) || result.confidence < 0 || result.confidence > 1 ||
          (final ? typeof result.source !== 'string' || !result.source.trim() :
            typeof category.model !== 'string' || !category.model.trim() || !['L1', 'L2', 'L3'].includes(String(category.level)))) throw new GuardRejected('unverified');
    }
    ids.push(job.job_id);
  }
  return ids;
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
