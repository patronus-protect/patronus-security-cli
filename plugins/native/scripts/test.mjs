import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createServer } from 'node:net'
import { root, bundle } from './builder.mjs'

const scratch = await mkdtemp(join(tmpdir(), 'patronus-native-tests-'))
try {
  const available = (await readdir(resolve(root, 'tests'))).filter(name => name.endsWith('.test.ts'))
  const files = process.argv.length > 2 ? process.argv.slice(2) : available
  if (files.some(name => !available.includes(name))) throw Error('Unknown native test file.')
  if (files.includes('broker.test.ts')) {
    const requirement = 'Native broker tests require Unix sockets and process inspection. Run with local host permissions; a restricted sandbox cannot exercise the broker.'
    if (process.platform === 'darwin') {
      const probe = spawnSync('/bin/ps', ['-p', String(process.pid), '-o', 'lstart='], { encoding: 'utf8', timeout: 2000 })
      if (probe.error || probe.status !== 0 || !probe.stdout.trim()) throw Error(requirement)
    }
    const server = createServer()
    try {
      await new Promise((resolveReady, reject) => {
        server.once('error', reject)
        server.listen(join(scratch, 'p'), resolveReady)
      })
    } catch { throw Error(requirement) }
    finally { if (server.listening) await new Promise(resolveClosed => server.close(resolveClosed)) }
  }
  const outputs = []
  for (const name of files) {
    const output = join(scratch, name.replace('.ts', '.mjs'))
    await writeFile(output, await bundle(resolve(root, 'tests', name), output))
    outputs.push(output)
  }
  const result = spawnSync(process.execPath, ['--test', '--test-concurrency=1', ...outputs], {
    stdio: 'inherit', env: { ...process.env, PATRONUS_NATIVE_BUNDLE: resolve(root, 'dist/patronus.mjs') }, timeout: 360_000,
  })
  if (result.error) throw result.error
  process.exitCode = result.status ?? 1
} finally { await rm(scratch, { recursive: true, force: true }) }
