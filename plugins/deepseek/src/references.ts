/** Static document IDs and runtime job IDs are different capabilities. Never guess a mapping. */
export function invalidScanReference(scanId: unknown) {
  const file = typeof scanId === 'string' && /^(?:file_)?[a-f0-9]{64}$/.test(scanId)
  if (!file && typeof scanId === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(scanId)) return undefined
  return {
    status: 'invalid_reference',
    code: file ? 'wrong_id_type' : 'invalid_scan_id',
    expected: 'runtime_scan_id',
    message: file
      ? 'This is a static file_id, not a runtime scan_id. Static scan findings do not create a retrievable runtime result. Use the scan_id from a pending or dangerous tool-result receipt. Do not retry this file_id or disable the integration.'
      : 'Use the exact scan_id from the Patronus tool-result receipt. No scan was retrieved; this does not indicate a scanner outage.',
  }
}

export function unavailableScanReference() {
  return { status: 'invalid_reference', code: 'scan_not_available', expected: 'runtime_scan_id',
    message: 'This scan_id is unknown, expired, or belongs to another session. Use the scan_id from this session’s Patronus tool-result receipt. This is not a scanner outage.' }
}
