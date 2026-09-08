import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstat, mkdir, mkdtemp, realpath, rm, stat, writeFile } from 'node:fs/promises'
import { patronusRoot } from './settings.ts'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import { executablePath, type LocalClientConfig } from './client.ts'

const SCHEMA = 'patronus.deepseek.static.v1'
const MAX_REPORT_BYTES = 8 * 1024 * 1024
const MAX_FINDINGS = 50
const categories = ['prompt_injection', 'injection', 'dlp', 'pii', 'threat']
const levels = ['l1', 'l2', 'l3']
const record = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)
const count = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0
const failure = () => new Error('Patronus static scan unavailable.')
const failed = (reason = 'scan_unavailable'): JsonValue => ({ schema: SCHEMA, status: 'FAILED', approved: false, reason })

/** The CLI prints its complete effective config. Freeze it so repository settings
 * cannot enable downloads, change provider, or retain evidence during this scan. */
function toml(value: unknown): string {
  if (typeof value === 'string' || typeof value === 'boolean' || count(value)) return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(toml).join(', ')}]`
  if (record(value)) return `{ ${Object.entries(value).map(([key, item]) => `${JSON.stringify(key)} = ${toml(item)}`).join(', ')} }`
  throw failure()
}

/** Never return process diagnostics or parser exception strings to the host. */
function run(executable: string, args: string[], cwd: string, limit: number, signal: AbortSignal): Promise<{ code: number; value: unknown }> {
  return new Promise((resolveResult, reject) => {
    if (signal.aborted) { reject(failure()); return }
    const child = spawn(executable, args, { cwd, shell: false, stdio: ['ignore', 'pipe', 'pipe'] })
    let chunks: Buffer[] = []
    let bytes = 0
    let diagnostics = 0
    let stopped = false
    let settled = false
    let killTimer: ReturnType<typeof setTimeout> | undefined
    let settleTimer: ReturnType<typeof setTimeout> | undefined
    const finish = (code: number | null) => {
      if (settled) return
      settled = true
      clearTimeout(killTimer)
      clearTimeout(settleTimer)
      signal.removeEventListener('abort', stop)
      child.stdout.destroy()
      child.stderr.destroy()
      try {
        if (stopped || signal.aborted || code === null) throw failure()
        const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, bytes)))
        resolveResult({ code, value })
      } catch { reject(failure()) }
      chunks = []
    }
    const stop = () => {
      if (stopped || settled) return
      stopped = true
      chunks = []
      child.kill('SIGTERM')
      killTimer = setTimeout(() => child.kill('SIGKILL'), 250)
      // Bound host disposal even if an inherited pipe never closes.
      settleTimer = setTimeout(() => finish(null), 1_000)
    }
    child.stdout.on('data', (chunk: Buffer) => {
      if (stopped) return
      bytes += chunk.length
      if (bytes > limit) stop()
      else chunks.push(chunk)
    })
    child.stderr.on('data', (chunk: Buffer) => {
      diagnostics += chunk.length
      if (diagnostics > 1024 * 1024) stop()
    })
    child.once('error', () => { stopped = true; finish(null) })
    child.once('close', finish)
    signal.addEventListener('abort', stop, { once: true })
    if (signal.aborted) stop()
  })
}

/** Explicit projection: no report prose, paths, labels, evidence, or unknown fields. */
function summary(value: unknown, code: number, kind: string, provider: string): JsonValue {
  if (!record(value) || value.schema !== 'patronus.security-scanner.report.v1' || value.target_kind !== kind ||
      typeof value.status !== 'string' || !['CLEAN', 'FINDINGS', 'INCOMPLETE', 'FAILED'].includes(value.status) ||
      !record(value.coverage) || !Array.isArray(value.findings) ||
      !Array.isArray(value.ark_categories) || value.ark_categories.length === 0 || value.ark_categories.length > categories.length ||
      !value.ark_categories.every(item => typeof item === 'string' && categories.includes(item)) ||
      typeof value.ark_max_level !== 'string' || !levels.includes(value.ark_max_level)) throw failure()
  const coverage: Record<string, JsonValue> = {}
  for (const key of ['discovered_files', 'eligible_files', 'analyzed_files', 'skipped_files', 'eligible_bytes', 'analyzed_bytes', 'chunks', 'classifications', 'failures']) {
    if (!count(value.coverage[key])) throw failure()
    coverage[key] = value.coverage[key]
  }
  if (typeof value.coverage.degraded !== 'boolean') throw failure()
  coverage.degraded = value.coverage.degraded
  coverage.complete = coverage.eligible_files !== 0 && coverage.discovered_files === coverage.eligible_files &&
    coverage.analyzed_files === coverage.eligible_files && coverage.analyzed_bytes === coverage.eligible_bytes &&
    coverage.skipped_files === 0 && coverage.failures === 0 && !coverage.degraded
  if ((value.status === 'INCOMPLETE' ? code !== 3 : code !== 0) ||
      (value.status === 'CLEAN' && value.findings.length !== 0) ||
      (value.status === 'FINDINGS' && value.findings.length === 0)) throw failure()
  const findings = value.findings.slice(0, MAX_FINDINGS).map(item => {
    if (!record(item) || typeof item.path !== 'string' || typeof item.category !== 'string' || !categories.includes(item.category) ||
        typeof item.level !== 'string' || !levels.includes(item.level) || !count(item.line_start) || !count(item.line_end) ||
        item.line_end < item.line_start || typeof item.confidence !== 'number' ||
        !Number.isFinite(item.confidence) || item.confidence < 0 || item.confidence > 1) throw failure()
    return {
      file_id: `file_${createHash('sha256').update(item.path).digest('hex')}`,
      category: item.category as string, level: item.level as string,
      line_start: item.line_start, line_end: item.line_end, confidence: item.confidence,
    }
  })
  const status = !coverage.complete && value.status === 'CLEAN' ? 'INCOMPLETE' : value.status as string
  return {
    schema: SCHEMA, status, approved: status === 'CLEAN' && coverage.complete === true,
    provider, kind, categories: value.ark_categories as string[], max_level: value.ark_max_level as string,
    coverage, findings_count: value.findings.length, findings, findings_truncated: value.findings.length > MAX_FINDINGS,
    reference_kind: 'static_file', runtime_result_available: false,
  }
}

/** One bounded static invocation per plugin; source bytes are read only by the CLI. */
export class StaticScanner {
  private active?: Promise<JsonValue>
  constructor(private readonly config: LocalClientConfig, private readonly signal: AbortSignal, private readonly timeoutMs = 300_000) {}

  scan(input: unknown, signal: AbortSignal): Promise<JsonValue> {
    if (this.active) return Promise.resolve(failed('busy'))
    this.active = this.perform(input, signal).finally(() => { this.active = undefined })
    return this.active
  }

  async close(): Promise<void> { await this.active }

  private async remote(input: Record<string, unknown>, signal: AbortSignal): Promise<JsonValue> {
    if (typeof input.path !== 'string' || !input.path || input.path.includes('\0') || input.path.length > 8192 ||
        Object.keys(input).some(key => !['kind','path','server'].includes(key)) ||
        input.server !== undefined && (input.kind !== 'mcp' || typeof input.server !== 'string' || !input.server || input.server.length > 256)) throw failure()
    const executable = await realpath(executablePath(this.config.executable))
    const cwd = await realpath(process.cwd())
    for (let root = cwd; ; root = dirname(root)) {
      let repository = root === cwd
      try { await lstat(join(root,'.git')); repository = true } catch(error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw failure() }
      if (repository) { const within=relative(root,executable);if(within==='' || within!=='..' && !within.startsWith(`..${sep}`) && !isAbsolute(within)) throw failure() }
      if(dirname(root)===root)break
    }
    const args = ['scan', String(input.kind), '--format', 'json']
    if(this.config.configPath)args.push('--config',this.config.configPath)
    if(input.server !== undefined)args.push('--server',String(input.server))
    args.push('--',input.path)
    const {code,value} = await run(executable,args,cwd,MAX_REPORT_BYTES,signal)
    if(!record(value) || value.schema!=='patronus.remote.scan.v1' || value.kind!==input.kind || value.provider!=='api' ||
      value.complete!==true || typeof value.approved!=='boolean' || typeof value.status!=='string' || !['CLEAN','FINDINGS'].includes(value.status) ||
      (value.approved ? code!==0 || value.status!=='CLEAN' : code!==1 || value.status!=='FINDINGS') ||
      !count(value.jobs) || value.jobs===0 || !count(value.duration_ms) || !Array.isArray(value.categories) || !value.categories.length ||
      !value.categories.every(c=>typeof c==='string' && categories.includes(c)) || !Array.isArray(value.findings))throw failure()
    const findings=value.findings.slice(0,MAX_FINDINGS).map(item=>{
      if(!record(item)||typeof item.category!=='string'||!categories.includes(item.category)||typeof item.level!=='string'||!levels.includes(item.level)||typeof item.confidence!=='number'||!Number.isFinite(item.confidence)||item.confidence<0||item.confidence>1)throw failure()
      return {category:String(item.category),level:String(item.level),confidence:item.confidence}
    })
    if(value.approved !== (value.findings.length===0))throw failure()
    return {schema:'patronus.remote.scan.v1',kind:String(input.kind),provider:'api',status:String(value.status),approved:value.approved,complete:true,
      categories:value.categories as string[],findings,findings_count:value.findings.length,findings_truncated:value.findings.length>MAX_FINDINGS,jobs:value.jobs,duration_ms:value.duration_ms,runtime_result_available:false}
  }

  private async perform(input: unknown, callerSignal: AbortSignal): Promise<JsonValue> {
    let scratch: string | undefined
    let phase = 'scan_unavailable'
    const timeout = AbortSignal.timeout(this.timeoutMs)
    const signal = AbortSignal.any([callerSignal, this.signal, timeout])
    try {
      if (record(input) && typeof input.kind === 'string' && ['url', 'mcp'].includes(input.kind)) return await this.remote(input, signal)
      if (signal.aborted || !record(input) || typeof input.kind !== 'string' || !['repo', 'directory', 'file'].includes(input.kind) ||
          typeof input.path !== 'string' || !input.path || input.path.length > 4096 || input.path.includes('\0') ||
          Object.keys(input).some(key => key !== 'kind' && key !== 'path')) throw failure()
      const target = resolve(input.path)
      const executable = await realpath(executablePath(this.config.executable))
      const metadata = input.kind === 'file' ? await lstat(target) : await stat(target)
      // Do not dereference an explicit symlink file: the CLI owns its skip policy.
      const targetRoot = await realpath(metadata.isDirectory() ? target : dirname(target))
      const excluded = [await realpath(process.cwd()), targetRoot]
      // A repo invocation may start in a subdirectory. Metadata-only ancestry
      // checks keep an executable elsewhere in that repository untrusted too.
      for (let root = targetRoot; ; root = dirname(root)) {
        try { await lstat(join(root, '.git')); excluded.push(root); break }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw failure() }
        if (dirname(root) === root) break
      }
      for (const root of excluded) {
        const within = relative(root, executable)
        if (within === '' || (!within.startsWith(`..${sep}`) && within !== '..' && !isAbsolute(within))) throw failure()
      }
      const configArgs = ['config', 'print', '--format', 'json']
      let configured = this.config.configPath === undefined ? undefined : resolve(this.config.configPath)
      if (configured === undefined) {
        // Plugin configuration is shared across repositories.
        const projectConfig = join(patronusRoot(), 'config.toml')
        try { await lstat(projectConfig); configured = projectConfig }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw failure() }
      }
      if (configured !== undefined) configArgs.push('--config', configured)
      phase = 'configuration_unavailable'
      const printed = await run(executable, configArgs, process.cwd(), 1024 * 1024, signal)
      if (printed.code !== 0 || !record(printed.value) || printed.value.schema_version !== 1 || !record(printed.value.provider)) throw failure()
      if (!['local', 'api', 'hybrid'].includes(String(printed.value.provider.mode))) return failed('unsupported_provider')
      const config = printed.value
      for (const table of ['ark', 'scan', 'ignore', 'chunking', 'output', 'progress', 'support', 'runtime']) {
        if (!record(config[table])) throw failure()
      }
      phase = 'storage_unavailable'
      const root = patronusRoot()
      await mkdir(join(root, 'tmp'), { recursive: true, mode: 0o700 })
      scratch = await mkdtemp(join(root, 'tmp', 'static-')) // mode 0700
      const output = join(root, 'output')
      config.ark = { ...config.ark as object, download_files: false }
      config.output = { ...config.output as object, root: output, include_evidence_text: false, include_chunk_content: false, write_progress_events: false }
      const configPath = join(scratch, 'scan.toml')
      await writeFile(configPath, Object.entries(config).map(([key, value]) => `${JSON.stringify(key)} = ${toml(value)}`).join('\n'), { mode: 0o600, flag: 'wx' })
      phase = 'scan_unavailable'
      const result = await run(executable, [
        'scan', input.kind as string, '--no-repo-config', '--config', configPath, '--output', output,
        '--format', 'json', '--progress', 'off', '--color', 'never', '--fail-on', 'incomplete', '--', target,
      ], scratch, MAX_REPORT_BYTES, signal)
      return summary(result.value, result.code, input.kind as string, printed.value.provider.mode === 'api' ? 'api' : 'local')
    } catch { return failed(timeout.aborted ? 'timeout' : signal.aborted ? 'aborted' : phase) }
    finally {
      if (scratch) {
        try { await rm(scratch, { recursive: true, force: true }) }
        catch { return failed('cleanup_failed') }
      }
    }
  }
}
