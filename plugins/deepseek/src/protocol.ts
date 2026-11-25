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
export interface CommandParams { host?: string; session: string; tool: string; call_id: string; command: string; cwd?: string; home?: string; repo_root?: string }
/** Ark Core's attack classes; with `pii` and `dlp` they are the scanner's categories. */
export const ATTACK_CLASSES = ['injection', 'jailbreak', 'prompt_extraction', 'tool_poisoning', 'agent_config_tampering', 'memory_poisoning',
  'exfiltration', 'unsafe_action', 'resource_exhaustion', 'harmful_content', 'toxic_language'] as const
export const SCAN_CATEGORIES: readonly string[] = ['pii', 'dlp', ...ATTACK_CLASSES]
/** L1: rules and L1 models; L3: Wolf Defender Edge for injection. */
export const SCAN_LEVELS: readonly string[] = ['l1', 'l3']
export const isAttackClass = (category: unknown): boolean => typeof category === 'string' && (ATTACK_CLASSES as readonly string[]).includes(category)
/** Readable category names for messages to people. */
export const CATEGORY_LABELS: Record<string, string> = {
  pii: 'personal data', dlp: 'sensitive data', injection: 'prompt injection', jailbreak: 'jailbreak attempt', prompt_extraction: 'prompt extraction',
  tool_poisoning: 'tool poisoning', agent_config_tampering: 'agent configuration tampering', memory_poisoning: 'memory poisoning',
  exfiltration: 'data exfiltration', unsafe_action: 'unsafe action', resource_exhaustion: 'resource exhaustion', harmful_content: 'harmful content',
  toxic_language: 'toxic language',
}
/** Pre-execution shell command check; `risk` is set for a dangerous command. */
export interface CommandResult { status: 'approved' | 'dangerous' | 'unavailable'; category: 'shell_command'; risk?: 'low' | 'medium'; decision_score?: number; threshold?: number; reason?: string }
export interface ScanResult {
  scan_id: string
  status: ScanStatus
  cached?: boolean
  job_status?: string
  findings?: JsonValue
  coverage?: JsonValue
  redacted_available?: boolean
  result?: JsonValue
  /** Fixed public explanation, e.g. a local fallback after the API usage limit or an expired login. */
  notice?: ScanNotice
  /** Only fixed, public failure codes such as usage_limit_reached or authentication_expired. */
  reason?: string
}
export interface ScanNotice {
  code: 'api_usage_limit' | 'api_authentication_missing' | 'api_authentication_expired' | 'api_authentication_rejected'
  fallback: 'local' | 'none'
  retry_after?: number
}
export interface RedactedResult {
  scan_id: string
  status: 'redacted' | 'unavailable'
  result?: JsonValue
}

/** PII types a user can confirm for one-time disclosure; mirrors the runtime's fixed list. */
export const PII_TYPES = ['email', 'ip_address', 'phone', 'mac_address', 'iban', 'credit_card', 'swift_code', 'financial_account', 'date_of_birth', 'username', 'employee_id', 'customer_id', 'patient_id', 'student_id', 'applicant_id', 'tax_id', 'social_id', 'health_insurance_id', 'physician_id', 'passport_number', 'id_card_number', 'driver_license', 'license_plate', 'ssn', 'national_id'] as const
export type PiiType = typeof PII_TYPES[number]
export interface DisclosureParams { session: string; scan_id: string; reveal_pii: PiiType[] }
export interface DisclosedParams { session: string; scan_id: string; grant_id: string }
/** An offer carries counts per type, never values. */
export interface DisclosureOffer {
  scan_id: string
  status: 'confirmation_required' | 'nothing_to_reveal' | 'unavailable'
  grant_id?: string
  counts?: Partial<Record<PiiType, number>>
  expires_in_seconds?: number
}
export interface DisclosedResult {
  scan_id: string
  status: 'redacted' | 'disclosure_expired' | 'disclosure_invalid' | 'disclosure_unavailable' | 'unavailable'
  result?: JsonValue
  disclosure?: { authorized_pii_types: PiiType[]; user_confirmed: true }
}

/** Transport boundary; tests inject this interface, never a model-accessible backend. */
export interface RuntimeClient {
  hello(signal?: AbortSignal): Promise<RuntimeHello>
  submit(params: SubmitParams, signal?: AbortSignal): Promise<{ scan_id: string; status: 'pending' }>
  check(params: JobParams, signal?: AbortSignal): Promise<ScanResult>
  readRedacted(params: JobParams, signal?: AbortSignal): Promise<RedactedResult>
  cancel(params: JobParams, signal?: AbortSignal): Promise<unknown>
  /** Scanners before 0.1.10 do not offer it; callers then let the command run. */
  checkCommand?(params: CommandParams, signal?: AbortSignal): Promise<CommandResult>
  /** Only a trusted adapter calls these, after the host's own approval dialog. */
  prepareDisclosure?(params: DisclosureParams, signal?: AbortSignal): Promise<DisclosureOffer>
  readDisclosed?(params: DisclosedParams, signal?: AbortSignal): Promise<DisclosedResult>
  close(): void | Promise<void>
}
