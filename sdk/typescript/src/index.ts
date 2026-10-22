export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export interface ScanJob {
  job_id: string;
  source?: string;
  status?: string;
  progress?: Record<string, Json>;
  decision?: string;
  categories?: Record<string, Json>;
  [key: string]: Json | undefined;
}

export interface ScanResponse {
  ark_version?: string;
  status: string;
  jobs: ScanJob[];
  input?: Json;
  extraction?: Json;
  coverage?: Json;
  usage?: Json;
  request_id?: string;
  [key: string]: Json | ScanJob[] | undefined;
}

export type ErrorKind = "authentication" | "quota" | "rate_limit" | "validation" | "timeout" | "transport" | "protocol";

export class PatronusError extends Error {
  constructor(
    message: string,
    readonly kind: ErrorKind,
    readonly status?: number,
    readonly code?: string,
    readonly requestId?: string,
    readonly retryAfter?: number,
    readonly details?: Json,
    /** `quota.limit_kind` from a quota error body, e.g. "monthly_scan_units". */
    readonly limitKind?: string,
  ) { super(message); this.name = "PatronusError"; }
}

export interface ClientOptions {
  apiKey: string;
  baseUrl?: string;
  timeoutMs?: number;
  pollIntervalMs?: number;
  fetch?: typeof globalThis.fetch;
}

/** Per-request options for POST /scan. */
export interface RequestOptions {
  /** Idempotency-Key header: 1-128 visible ASCII characters. Reuse the same key when retrying the same request. */
  idempotencyKey?: string;
}

export interface UploadOptions extends RequestOptions {
  text?: string;
  config?: Json;
}

export interface Upload {
  name: string;
  data: Blob;
  mediaType?: string;
}

const DEFAULT_BASE_URL = "https://control.patronus.studio/api/v1";
const JOB_ID = /^job_[0-9a-f]{32}$/i;
/** Accepted.jobs and CompletedSubmission.jobs maxItems in the pinned OpenAPI contract. */
const MAX_JOBS = 100;
const IDEMPOTENCY_KEY = /^[\x21-\x7e]{1,128}$/;
const ENVELOPE_FIELDS = ["ark_version", "input", "extraction", "coverage", "usage", "request_id"] as const;

export class Patronus {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly pollIntervalMs: number;
  private readonly fetcher: typeof globalThis.fetch;

  constructor(private readonly options: ClientOptions) {
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this.pollIntervalMs = options.pollIntervalMs ?? 1_000;
    this.fetcher = options.fetch ?? globalThis.fetch;
    if (!options.apiKey.trim() || /[\r\n]/.test(options.apiKey)) throw new PatronusError("API key is required", "authentication");
    const url = new URL(this.baseUrl);
    const local = url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if ((url.protocol !== "https:" && !local) || url.username || url.password || url.search || url.hash) {
      throw new PatronusError("API base URL must use HTTPS without credentials, query, or fragment", "validation");
    }
  }

  scanText(text: string, config?: Json, options?: RequestOptions) { return this.scanJson({ text, ...(config === undefined ? {} : { config }) }, options); }
  scanUrl(url: string, config?: Json, options?: RequestOptions) { return this.scanJson({ url, ...(config === undefined ? {} : { config }) }, options); }
  scanMcpServer(mcp_server_url: string, config?: Json, options?: RequestOptions) { return this.scanJson({ mcp_server_url, ...(config === undefined ? {} : { config }) }, options); }

  async scanFiles(files: Upload[], options: UploadOptions = {}): Promise<ScanResponse> {
    if (!files.length) throw new PatronusError("At least one file is required", "validation");
    const headers = this.postHeaders(options);
    const form = new FormData();
    for (const file of files) form.append("files", file.mediaType ? new Blob([file.data], { type: file.mediaType }) : file.data, file.name);
    if (options.text !== undefined) form.append("text", options.text);
    if (options.config !== undefined) form.append("config", JSON.stringify(options.config));
    const deadline = Date.now() + this.timeoutMs;
    return this.wait(this.normalizeSubmission(await this.request("/scan", { method: "POST", headers, body: form }, deadline)), deadline);
  }

  scanFile(file: Upload, options: UploadOptions = {}) {
    return this.scanFiles([file], options);
  }

  async submit(body: Json, options?: RequestOptions): Promise<ScanResponse> {
    const headers = { "Content-Type": "application/json", ...this.postHeaders(options) };
    return this.normalizeSubmission(await this.request("/scan", { method: "POST", headers, body: JSON.stringify(body) }, Date.now() + this.timeoutMs));
  }

  async getJob(jobId: string): Promise<ScanJob> {
    if (!JOB_ID.test(jobId)) throw new PatronusError("Invalid API job identifier", "protocol");
    return this.request(`/scan/${jobId}`, {}, Date.now() + this.timeoutMs) as Promise<ScanJob>;
  }

  async scanJson(body: Json, options?: RequestOptions): Promise<ScanResponse> {
    const headers = { "Content-Type": "application/json", ...this.postHeaders(options) };
    const deadline = Date.now() + this.timeoutMs;
    const submission = this.normalizeSubmission(await this.request("/scan", { method: "POST", headers, body: JSON.stringify(body) }, deadline));
    return this.wait(submission, deadline);
  }

  private postHeaders(options?: RequestOptions): Record<string, string> {
    const key = options?.idempotencyKey;
    if (key === undefined) return { Prefer: "wait=1" };
    if (typeof key !== "string" || !IDEMPOTENCY_KEY.test(key)) throw new PatronusError("Idempotency key must be 1-128 visible ASCII characters", "validation");
    return { Prefer: "wait=1", "Idempotency-Key": key };
  }

  private normalizeSubmission(value: Json): ScanResponse {
    if (!value || typeof value !== "object" || Array.isArray(value)) return value as unknown as ScanResponse;
    if (Array.isArray(value.jobs)) return value as ScanResponse;
    if (!["completed", "failed"].includes(String(value.status)) || typeof value.job_id !== "string" || !JOB_ID.test(value.job_id)) {
      return value as ScanResponse;
    }

    const job = { ...value } as Record<string, Json | undefined>;
    const response: Record<string, Json | ScanJob[] | undefined> = { status: "completed", jobs: [job as ScanJob] };
    for (const field of ENVELOPE_FIELDS) {
      delete job[field];
      if (value[field] !== undefined) response[field] = value[field];
    }
    return response as ScanResponse;
  }

  private async wait(submission: ScanResponse, deadline: number): Promise<ScanResponse> {
    if (submission.status === "completed") {
      if (!Array.isArray(submission.jobs) || !submission.jobs.length || submission.jobs.length > MAX_JOBS || submission.jobs.some(job => !JOB_ID.test(job.job_id) || !["completed", "failed"].includes(job.status ?? ""))) {
        throw new PatronusError("Invalid completed API response", "protocol");
      }
      return submission;
    }
    if (submission.status !== "accepted" || !Array.isArray(submission.jobs) || !submission.jobs.length || submission.jobs.length > MAX_JOBS) throw new PatronusError("Invalid API jobs", "protocol");
    const jobs: ScanJob[] = [];
    for (const accepted of submission.jobs) {
      if (!JOB_ID.test(accepted.job_id)) throw new PatronusError("Invalid API job identifier", "protocol");
      while (true) {
        const job = await this.request(`/scan/${accepted.job_id}`, {}, deadline) as ScanJob;
        if (job.status === "queued" || job.status === "running") {
          await new Promise(resolve => setTimeout(resolve, Math.min(this.pollIntervalMs, this.remaining(deadline))));
        } else if (job.status) { jobs.push(job); break; }
        else throw new PatronusError("Missing API job status", "protocol");
      }
    }
    return { ...submission, status: jobs.every(job => job.status === "completed") ? "completed" : "failed", jobs };
  }

  private remaining(deadline: number) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new PatronusError("API scan timeout", "timeout");
    return remaining;
  }

  private async request(path: string, init: RequestInit, deadline: number): Promise<Json> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.remaining(deadline));
    try {
      const response = await this.fetcher(`${this.baseUrl}${path}`, {
        ...init,
        redirect: "error",
        signal: controller.signal,
        headers: { Accept: "application/json", Authorization: `Bearer ${this.options.apiKey}`, ...init.headers },
      });
      const declared = Number(response.headers.get("content-length"));
      if (Number.isFinite(declared) && declared > 1_048_576) throw new PatronusError("API response exceeds limit", "protocol", response.status);
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let text = "", bytes = 0;
      if (reader) {
        try {
          while (true) {
            const chunk = await reader.read();
            if (chunk.done) break;
            bytes += chunk.value.byteLength;
            if (bytes > 1_048_576) {
              await reader.cancel();
              throw new PatronusError("API response exceeds limit", "protocol", response.status);
            }
            text += decoder.decode(chunk.value, { stream: true });
          }
          text += decoder.decode();
        } finally { reader.releaseLock(); }
      }
      let value: Json;
      try { value = JSON.parse(text) as Json; }
      catch { throw new PatronusError("Invalid API response", "protocol", response.status); }
      if (!response.ok) throw this.httpError(response, value);
      return value;
    } catch (error) {
      if (error instanceof PatronusError) throw error;
      if (controller.signal.aborted) throw new PatronusError("API scan timeout", "timeout");
      throw new PatronusError("API request failed", "transport");
    } finally { clearTimeout(timer); }
  }

  private httpError(response: Response, value: Json) {
    const root = value && typeof value === "object" && !Array.isArray(value) ? value : {};
    const nested = "error" in root && root.error && typeof root.error === "object" && !Array.isArray(root.error) ? root.error : root;
    const code = typeof nested.code === "string" ? nested.code : undefined;
    const message = typeof nested.message === "string" ? nested.message : "API request failed";
    const requestId = typeof nested.request_id === "string" ? nested.request_id : response.headers.get("x-request-id") ?? undefined;
    const quota = "quota" in root && root.quota && typeof root.quota === "object" && !Array.isArray(root.quota) ? root.quota : undefined;
    const kind: ErrorKind = quota ? "quota" : response.status === 401 || response.status === 403 ? "authentication" : response.status === 429 && code?.includes("QUOTA") ? "quota" : response.status === 429 ? "rate_limit" : [400, 404, 409, 413, 422].includes(response.status) ? "validation" : "transport";
    const retryHeader = response.headers.get("retry-after");
    const headerRetry = retryHeader === null ? undefined : Number(retryHeader);
    const bodyRetry = quota?.retry_after;
    const retryAfter = headerRetry !== undefined && Number.isFinite(headerRetry) ? headerRetry
      : typeof bodyRetry === "number" && Number.isInteger(bodyRetry) && bodyRetry >= 0 ? bodyRetry : undefined;
    const limitKind = typeof quota?.limit_kind === "string" ? quota.limit_kind : undefined;
    return new PatronusError(message, kind, response.status, code, requestId, retryAfter, value, limitKind);
  }
}
