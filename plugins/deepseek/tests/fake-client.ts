import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import type { JobParams, RuntimeClient, RuntimeHello, ScanResult, SubmitParams } from '../src/protocol.ts'

export type TestVerdict = { status: 'approved' } | { status: 'dangerous'; redacted?: ContentBlock[] }
export interface TestScanner { scan(text: JsonValue): Promise<TestVerdict> }

export class FakeClient implements RuntimeClient {
  readonly submissions: SubmitParams[] = []
  private jobs = new Map<string, { session: string; state: ScanResult; redacted?: JsonValue }>()
  constructor(private scanner: TestScanner, private timeout = 5000) {}
  async hello(): Promise<RuntimeHello> {
    return { protocol_version: 1, provider: 'local', scanner_version: 'test', ark_version: 'test', ready: true,
      runtime: { response_wait_ms: 500, request_timeout_ms: 30000, scan_timeout_ms: this.timeout, max_payload_bytes: 10485760 } }
  }
  async submit(input: SubmitParams) {
    this.submissions.push(structuredClone(input))
    const scan_id = crypto.randomUUID()
    const job: { session: string; state: ScanResult; redacted?: JsonValue } = {
      session: input.session, state: { scan_id, status: 'pending', job_status: 'queued' },
    }
    this.jobs.set(scan_id, job)
    const timer = setTimeout(() => { if (job.state.status === 'pending') job.state = { scan_id, status: 'failed' } }, this.timeout)
    void this.scanner.scan(input.payload).then(verdict => {
      if (job.state.status !== 'pending') return
      if (verdict.status === 'approved') job.state = { scan_id, status: 'approved', result: input.payload }
      else {
        job.state = { scan_id, status: 'dangerous', redacted_available: verdict.redacted !== undefined }
        if (verdict.redacted) job.redacted = { content: verdict.redacted as unknown as JsonValue, isError: false }
      }
    }, () => { job.state = { scan_id, status: 'failed' } }).finally(() => clearTimeout(timer))
    return { scan_id, status: 'pending' as const }
  }
  async check(params: JobParams): Promise<ScanResult> {
    const job = this.jobs.get(params.scan_id)
    return structuredClone(job?.session === params.session ? job.state : { scan_id: params.scan_id, status: 'unavailable' })
  }
  async readRedacted(params: JobParams) {
    const job = this.jobs.get(params.scan_id)
    return job?.session === params.session && job.state.status === 'dangerous' && job.redacted !== undefined
      ? { scan_id: params.scan_id, status: 'redacted' as const, result: structuredClone(job.redacted) }
      : { scan_id: params.scan_id, status: 'unavailable' as const }
  }
  async cancel(params: JobParams) {
    const job = this.jobs.get(params.scan_id)
    if (job?.session === params.session && job.state.status === 'pending') job.state = { scan_id: params.scan_id, status: 'cancelled' }
  }
  close() { this.jobs.clear() }
}
