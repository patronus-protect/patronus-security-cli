import type { JsonValue } from '@deepseek-ai/dsh-util-values'

export type TextPayload = string | string[]

export type ScanStatus = 'pending' | 'approved' | 'redacted' | 'dangerous' | 'failed' | 'incomplete' | 'cancelled' | 'expired' | 'unavailable'
export interface RuntimeHello {
  protocol_version: 1
  provider: 'local' | 'api' | 'hybrid'
  scanner_version: string
  ark_version: string
  ready: true
  runtime: {
    response_wait_ms: number
    request_timeout_ms: number
    scan_timeout_ms: number
    max_payload_bytes: number
    [key: string]: JsonValue
  }
}
export interface SubmitParams {
  policy_scope?: string
  session: string
  direction: 'request' | 'response'
  tool: string
  call_id: string
  payload: TextPayload
}
export interface JobParams { session: string; scan_id: string }
export interface ScanResult {
  scan_id: string
  status: ScanStatus
  cached?: boolean
  job_status?: string
  findings?: JsonValue
  coverage?: JsonValue
  redacted_available?: boolean
  result?: JsonValue
  /** Fixed public explanation, e.g. a local fallback after the API usage limit. */
  notice?: ScanNotice
  /** Only fixed, public failure codes such as usage_limit_reached. */
  reason?: string
}
export interface ScanNotice {
  code: 'api_usage_limit'
  fallback: 'local' | 'none'
  retry_after?: number
}
export interface RedactedResult {
  scan_id: string
  status: 'redacted' | 'unavailable'
  result?: JsonValue
}

/** Transport boundary; tests inject this interface, never a model-accessible backend. */
export interface RuntimeClient {
  hello(signal?: AbortSignal): Promise<RuntimeHello>
  submit(params: SubmitParams, signal?: AbortSignal): Promise<{ scan_id: string; status: 'pending' }>
  check(params: JobParams, signal?: AbortSignal): Promise<ScanResult>
  readRedacted(params: JobParams, signal?: AbortSignal): Promise<RedactedResult>
  cancel(params: JobParams, signal?: AbortSignal): Promise<unknown>
  close(): void | Promise<void>
}
