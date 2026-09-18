import { describe, expect, it } from 'vitest'
import { DEGRADED_TEXT } from '../src/degraded.ts'
import { degradedText, noticeText, scanNotice } from '../src/notice.ts'
import { receipt } from '../src/receipts.ts'
import type { ScanResult } from '../src/protocol.ts'

const scan_id = 'a'.repeat(32)

describe('Patronus API usage limit notices', () => {
  it('accepts only the fixed notice shape', () => {
    expect(scanNotice({ code: 'api_usage_limit', fallback: 'local', retry_after: 120 }))
      .toEqual({ code: 'api_usage_limit', fallback: 'local', retry_after: 120 })
    expect(scanNotice({ code: 'api_usage_limit', fallback: 'none' })).toEqual({ code: 'api_usage_limit', fallback: 'none' })
    for (const value of [
      undefined, 'api_usage_limit', { code: 'other', fallback: 'local' }, { code: 'api_usage_limit', fallback: 'remote' },
      { code: 'api_usage_limit', fallback: 'local', retry_after: -1 }, { code: 'api_usage_limit', fallback: 'local', text: 'PRIVATE' },
    ]) expect(scanNotice(value)).toBeUndefined()
  })

  it('explains a local fallback with the retry time', () => {
    const text = noticeText({ code: 'api_usage_limit', fallback: 'local', retry_after: 600 })
    expect(text).toMatch(/API usage limit reached/)
    expect(text).toMatch(/scanned locally/)
    expect(text).toMatch(/600 seconds/)
  })

  it('names the usage limit instead of claiming the integration is inactive', () => {
    const failed: ScanResult = { scan_id, status: 'failed', reason: 'usage_limit_reached', notice: { code: 'api_usage_limit', fallback: 'none', retry_after: 30 } }
    expect(degradedText(failed)).toMatch(/API usage limit reached/)
    expect(degradedText(failed)).toMatch(/not scanned/)
    expect(degradedText(failed)).not.toMatch(/inactive/)
    expect(degradedText({ scan_id, status: 'failed' })).toBe(DEGRADED_TEXT)
    expect(degradedText({ scan_id, status: 'failed', reason: 'PRIVATE backend text' } as unknown as ScanResult)).toBe(DEGRADED_TEXT)
  })

  it('carries the notice and fixed reason in receipts', () => {
    const approved = receipt({ scan_id, status: 'approved', notice: { code: 'api_usage_limit', fallback: 'local' } }) as Record<string, unknown>
    expect(approved.notice).toEqual({ code: 'api_usage_limit', fallback: 'local' })
    const failed = receipt({ scan_id, status: 'failed', reason: 'usage_limit_reached', notice: { code: 'api_usage_limit', fallback: 'none' } }) as Record<string, unknown>
    expect(failed.reason).toBe('usage_limit_reached')
    expect(failed.message).toMatch(/API usage limit reached/)
  })
})
