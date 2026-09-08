import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export const canary = 'STATIC_PRIVATE_FILE_BYTES_741'
export const config = {
  schema_version: 1, provider: { mode: 'local' },
  ark: { categories: ['prompt_injection'], max_level: 'l1', download_files: true },
  output: { include_evidence_text: true, include_chunk_content: true },
  scan: { include_hidden: true, respect_gitignore: false, max_file_bytes: 123456 },
  ignore: { patterns: ['custom-ignore/**'] }, chunking: {}, progress: {}, support: {}, runtime: {},
}
export const report = {
  schema: 'patronus.security-scanner.report.v1', status: 'CLEAN',
  ark_categories: ['prompt_injection'], ark_max_level: 'l1',
  coverage: { discovered_files: 1, eligible_files: 1, analyzed_files: 1, skipped_files: 0,
    eligible_bytes: 30, analyzed_bytes: 30, chunks: 1, classifications: 1, failures: 0, degraded: false },
  findings: [],
  conclusion: canary, content: canary, evidence: canary, chunks: [{ content: canary }],
  failures: [{ message: canary }], skipped: [{ reason: canary }], report_path: canary,
}
export const finding = { path: canary, category: 'prompt_injection', level: 'l1', line_start: 1, line_end: 1, confidence: 0.99, label: canary, source: canary, evidence: canary }

/** This test-only installed executable simulates the CLI protocol, not Ark logic. */
export async function fakeCli(mode = 'normal', override: object = {}) {
  const root = await mkdtemp(join(tmpdir(), 'patronus-static-test-'))
  const targetDir = join(root, 'targets')
  await mkdir(targetDir)
  const path = join(targetDir, '--file $(echo literal); `echo literal` \' "\n.txt')
  await writeFile(path, canary)
  const executable = join(root, 'installed-scanner.mjs')
  const log = join(root, 'calls.jsonl')
  const configPath = join(root, 'settings \' " $literal.toml')
  await writeFile(configPath, 'test config placeholder')
  await writeFile(executable, `#!${process.execPath}
import { appendFileSync, readFileSync, statSync } from 'node:fs';
const args = process.argv.slice(2), first = args[0] === 'config';
const snapshot = first ? undefined : readFileSync(args[args.indexOf('--config') + 1], 'utf8');
appendFileSync(${JSON.stringify(log)}, JSON.stringify({args,cwd:process.cwd(),pid:process.pid,mode:statSync(process.cwd()).mode & 511,snapshot}) + '\\n');
const mode = ${JSON.stringify(mode)};
if (mode === 'hang-config' || (!first && mode === 'hang')) {
  process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);
} else if ((!first && mode === 'error') || (first && mode === 'config-error')) {
  process.stdout.write(${JSON.stringify(canary)}); process.stderr.write(${JSON.stringify(canary)}); process.exitCode = 4;
} else if (!first && mode === 'huge') {
  process.stdout.write('x'.repeat(9 * 1024 * 1024));
} else {
  const value = first ? ${JSON.stringify(config)} : {...${JSON.stringify({ ...report, ...override })}, target_kind: args[1]};
  if (first && ['api','hybrid','webmcp','missing-provider'].includes(mode)) value.provider = {mode: mode === 'missing-provider' ? undefined : mode};
  if ((!first && mode === 'noise') || (first && mode === 'config-noise')) process.stdout.write(${JSON.stringify(canary)} + '\\n');
  process.stderr.write(${JSON.stringify(canary)}); // never a host-visible diagnostic
  process.stdout.write(JSON.stringify(value));
  if (!first && value.status === 'INCOMPLETE') process.exitCode = 3;
}
`, { mode: 0o700 })
  return { root, targetDir, path, executable, configPath,
    async calls() { try { return (await readFile(log, 'utf8')).trim().split('\n').map(line => JSON.parse(line)) } catch { return [] } },
  }
}
