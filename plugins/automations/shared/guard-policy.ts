// Guard Input release policy: a pure decision over a completed Patronus scan response.
// It has no dependencies, timers or I/O so every platform (including the self-contained
// n8n package) evaluates exactly the same rules.

export const GUARD_CONFIG = { categories: ['injection', 'dlp'], max_level: 'L3' };
export const JOB_ID = /^job_[0-9a-f]{32}$/i;

export type GuardVerdict =
  | { status: 'allowed'; jobIds: string[] }
  | { status: 'blocked' | 'unverified' };

type ObjectValue = Record<string, unknown>;
const object = (value: unknown): ObjectValue => value && typeof value === 'object' && !Array.isArray(value) ? value as ObjectValue : {};

function completeMetadata(value: unknown): boolean {
  const metadata = object(value);
  return metadata.state === 'complete' && typeof metadata.documents_total === 'number' && Number.isInteger(metadata.documents_total) && metadata.documents_total >= 1 &&
    metadata.documents_total === metadata.documents_scanned &&
    (metadata.pages_total === undefined && metadata.pages_scanned === undefined ||
      typeof metadata.pages_total === 'number' && Number.isInteger(metadata.pages_total) && metadata.pages_total >= 1 && metadata.pages_total === metadata.pages_scanned);
}

export function evaluateGuardResult(value: unknown): GuardVerdict {
  const response = object(value);
  if (response.status !== 'completed' || !Array.isArray(response.jobs) || !response.jobs.length || response.jobs.length > 32) return { status: 'unverified' };
  const ids: string[] = [];
  for (const entry of response.jobs) {
    const job = object(entry);
    if (typeof job.job_id !== 'string' || !JOB_ID.test(job.job_id) || ids.includes(job.job_id) || job.status !== 'completed') return { status: 'unverified' };
    if (job.decision !== 'allow' || job.safety_status !== undefined && job.safety_status !== 'benign' ||
        response.decision !== undefined && response.decision !== 'allow' || response.safety_status !== undefined && response.safety_status !== 'benign') return { status: 'blocked' };
    const completion = object(job.completion);
    if (!completeMetadata(job.coverage === undefined ? response.coverage : job.coverage) || !completeMetadata(job.extraction === undefined ? response.extraction : job.extraction) ||
        completion.state !== 'complete' || completion.failures !== undefined && (!Array.isArray(completion.failures) || completion.failures.length > 0)) return { status: 'unverified' };
    const categories = object(job.categories);
    if (Object.keys(categories).length !== 2) return { status: 'unverified' };
    for (const name of GUARD_CONFIG.categories) {
      const category = object(categories[name]);
      const final = Object.prototype.hasOwnProperty.call(category, 'final_result');
      const result = final ? object(category.final_result) : category;
      if (result.class_name !== 'benign' && result.class_name !== 'safe') return { status: result.class_name ? 'blocked' : 'unverified' };
      // Use the API's final classification without re-thresholding detector candidates.
      if (typeof result.confidence !== 'number' || !Number.isFinite(result.confidence) || result.confidence < 0 || result.confidence > 1 ||
          (final ? typeof result.source !== 'string' || !result.source.trim() :
            typeof category.model !== 'string' || !category.model.trim() || !['L1', 'L2', 'L3'].includes(String(category.level)))) return { status: 'unverified' };
    }
    ids.push(job.job_id);
  }
  return { status: 'allowed', jobIds: ids };
}
