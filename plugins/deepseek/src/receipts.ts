import type { PostToolDecision } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import type { ScanResult } from './protocol.ts'

function hostProfile(): string {
  const index = process.argv.findIndex(value => value === '--profile')
  const candidate = index >= 0 ? process.argv[index + 1] : process.argv.find(value => value.startsWith('--profile='))?.slice(10)
  return candidate && /^[A-Za-z0-9_.-]{1,64}$/.test(candidate) ? candidate : 'headless'
}

export function receipt(result: ScanResult, direction: 'request' | 'response' = 'response', profile = hostProfile()): JsonValue {
  const metadata: Record<string, JsonValue> = { scan_id: result.scan_id, status: result.status }
  if (result.cached !== undefined) metadata.cached = result.cached
  if (result.findings !== undefined) metadata.findings = result.findings
  if (result.coverage !== undefined) metadata.coverage = result.coverage
  if (result.job_status !== undefined) metadata.job_status = result.job_status
  if (result.redacted_available !== undefined) metadata.redacted_available = result.redacted_available
  if (result.status === 'unavailable') {
    metadata.message = 'Patronus is unavailable or inactive. Check the DeepSeek integration status, then enable it or disable/uninstall it if scanning is not wanted.'
    metadata.recovery = {
      status: `patronus-security-scanner integration deepseek status --profile ${profile} --format json`,
      enable: `patronus-security-scanner integration deepseek enable --profile ${profile}`,
      disable: `patronus-security-scanner integration deepseek disable --profile ${profile}`,
      uninstall: `patronus-security-scanner integration deepseek uninstall --profile ${profile}`,
    }
  } else if (result.status === 'redacted' && direction === 'response') {
    metadata.result = result.result ?? null
    metadata.message = 'Use this redacted result to continue the task. Sensitive regions were masked; the original remains withheld. Do not rerun the source tool.'
  } else if (direction === 'request') {
    metadata.message = 'The user prompt did not receive complete security approval and was not sent to the model.'
  } else if (result.status === 'pending') {
    metadata.next_tool = 'patronus_check_result'
    if (result.job_status === 'queued') {
      metadata.wait_reason = 'scanner_queue'
      metadata.message = 'The source tool already executed once and its result is waiting in the Patronus scan queue because scanner capacity is busy. This is queue backpressure, not a scan failure or expiry. Keep this scan_id and call patronus_check_result later; do not rerun the source tool.'
    } else {
      metadata.message = 'The source tool already executed; its result is withheld. Continue any independent work, then call patronus_check_result with this scan_id. If still pending, call patronus_check_result again directly; do not use Bash, Monitor, or another source tool merely to wait. Use the original only after approval. Do not rerun the source tool.'
    }
  } else if (result.status === 'dangerous') {
    metadata.message = result.redacted_available
      ? 'The source tool already executed. Its original is permanently withheld. Call patronus_read_redacted with this scan_id to obtain the redacted result. Do not rerun the source tool.'
      : 'The source tool already executed. Its original is permanently withheld and no redacted result is available. Do not rerun the source tool.'
  } else if (result.status !== 'approved') {
    metadata.message = 'The scan did not provide complete approval. The original result is unavailable. The source tool may already have executed; do not repeat it merely to recover its result.'
  }
  return metadata
}

export function blocked(value: JsonValue): PostToolDecision {
  return { kind: 'block', feedback: [{ type: 'text', text: JSON.stringify(value) }] }
}

export const unavailable = (scan_id = ''): ScanResult => ({ status: 'unavailable', scan_id })
