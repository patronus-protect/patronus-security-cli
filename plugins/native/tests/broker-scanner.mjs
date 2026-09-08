// Deterministic test-only CLI protocol fixture; security detection is not simulated
// in the installed-CLI acceptance test. Never install this executable globally.
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { createInterface } from 'node:readline'
import { randomBytes } from 'node:crypto'

const options = JSON.parse(readFileSync(new URL('./options.json', import.meta.url), 'utf8'))
const args = process.argv.slice(2)
const log = new URL('./calls.jsonl', import.meta.url)
appendFileSync(log, JSON.stringify({ args, pid: process.pid }) + '\n')
const canary = 'BROKER_PRIVATE_PROTOCOL_CANARY731'
if (args[0] === 'config') {
  process.stdout.write(JSON.stringify({ schema_version: 1,
    provider: { mode: options.provider ?? 'local' },
    ark: { max_level: 'l1', categories: ['prompt_injection'], download_files: options.downloads ?? false },
    scan: {}, ignore: {}, chunking: {}, progress: {}, output: {}, support: {}, runtime: {},
  }))
} else {
  const state = args[args.indexOf('--state-dir') + 1]
  mkdirSync(state, { recursive: true, mode: 0o700 })
  const coverage = { complete: true, fields_total: 1, fields_scanned: 1, bytes_total: 1, bytes_scanned: 1 }
  const file = id => join(state, id + '.json')
  createInterface({ input: process.stdin }).on('line', line => {
    const { id, method, params } = JSON.parse(line)
    appendFileSync(new URL('./rpc.jsonl', import.meta.url), JSON.stringify({ method, policy_scope: params.policy_scope }) + '\n')
    const reply = result => process.stdout.write(JSON.stringify({ id, result }) + '\n')
    process.stderr.write(canary)
    if (options.noise) { process.stdout.write(canary + '\n'); return }
    if (options.error) { process.stdout.write(JSON.stringify({ id, error: { message: canary } }) + '\n'); return }
    if (method === 'hello') {
      reply({ protocol_version: 1, provider: options.helloProvider ?? 'local', scanner_version: '0.1.0', ark_version: options.arkVersion ?? '0.1.6', ready: true,
        runtime: { response_wait_ms: 0, request_timeout_ms: 1000, scan_timeout_ms: 60000, max_payload_bytes: options.payloadLimit ?? 10 * 1024 * 1024 } })
    } else if (method === 'submit') {
      const scan_id = randomBytes(16).toString('hex')
      writeFileSync(file(scan_id), JSON.stringify({ ...params, readyAt: Date.now() + (options.delayMs ?? 0) }), { mode: 0o600 })
      reply({ scan_id, status: 'pending' })
    } else {
      let job
      try { job = JSON.parse(readFileSync(file(params.scan_id), 'utf8')) } catch { reply({ scan_id: params.scan_id, status: 'unavailable' }); return }
      if (params.session !== job.session) { reply({ scan_id: params.scan_id, status: 'unavailable' }); return }
      if (method === 'cancel') { reply({ scan_id: params.scan_id, status: 'cancelled' }); return }
      const dangerous = options.dangerous === true
      if (method === 'read_redacted') { reply(dangerous ? { scan_id: params.scan_id, status: 'redacted', result: '[REDACTED]' } : { scan_id: params.scan_id, status: 'unavailable' }); return }
      const status = Date.now() < job.readyAt ? 'pending' : dangerous ? 'dangerous' : 'approved'
      reply({ scan_id: params.scan_id, status, coverage, job_status: 'completed',
        redacted_available: dangerous && job.direction === 'response',
        findings: dangerous ? [{ category: options.category ?? 'prompt_injection', level: 'l1', confidence: 1, label: canary }] : [],
        error: canary, metadata: canary,
        ...(status === 'approved' && job.direction === 'response' ? { result: job.payload } : {}),
      })
    }
  })
}
