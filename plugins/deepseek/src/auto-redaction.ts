import type { RedactedResult, ScanResult } from './protocol.ts'

const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value)

/** Privacy findings retain their verdict; only the scanner's masked view is released. */
export async function autoRedact(result: ScanResult, read: () => Promise<RedactedResult>): Promise<ScanResult> {
  const coverage = result.coverage
  if (result.status !== 'dangerous' || !result.redacted_available || !record(coverage) || coverage.complete !== true ||
      !['fields_total', 'fields_scanned', 'bytes_total', 'bytes_scanned'].every(key => Number.isSafeInteger(coverage[key]) && Number(coverage[key]) >= 0) ||
      coverage.fields_total !== coverage.fields_scanned || coverage.bytes_total !== coverage.bytes_scanned ||
      !Array.isArray(result.findings) || result.findings.length === 0 ||
      !result.findings.every(item => record(item) && (item.category === 'pii' || item.category === 'dlp'))) return result
  try {
    const masked = await read()
    if (masked.scan_id === result.scan_id && masked.status === 'redacted' &&
        (typeof masked.result === 'string' || Array.isArray(masked.result) && masked.result.every(item => typeof item === 'string'))) {
      return { ...result, status: 'redacted', result: masked.result }
    }
  } catch { /* Preserve the receipt and manual redaction route on retrieval failure. */ }
  return result
}
