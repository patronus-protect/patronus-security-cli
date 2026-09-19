import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const pluginRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
const modes = new Map([['--check-gpt', 'check'], ['--login-gpt', 'login'], ['--live-gpt', 'live'], ['--local', 'local'], ['--models', 'models'], ['--static-local', 'static-local']])
const mode = modes.get(args[0])
if (args.length > 1 || (args.length === 1 && !mode)) {
  throw new Error('Usage: test.mjs [--check-gpt | --login-gpt | --live-gpt | --local | --models | --static-local]')
}
const harnessRoot = process.env.DSH_SOURCE_ROOT && resolve(process.env.DSH_SOURCE_ROOT)
if (!harnessRoot) throw new Error('Set DSH_SOURCE_ROOT to the scanned, dependency-installed Harness checkout.')
const manifest = JSON.parse(await readFile(join(pluginRoot, 'package.json'), 'utf8'))
const revision = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: harnessRoot, encoding: 'utf8' })
if (revision.status !== 0 || revision.stdout.trim() !== manifest.patronusProbe.harnessCommit) {
  throw new Error(`This probe requires Harness commit ${manifest.patronusProbe.harnessCommit}`)
}
await mkdir(join(harnessRoot, 'tmp'), { recursive: true })
const scratch = await mkdtemp(join(harnessRoot, 'tmp', 'patronus-probe-'))
try {
  const mcpRequire = createRequire(join(harnessRoot, 'packages/mcp/mcp-client/package.json'))
  const aliases = {
    'harness-test-mock': join(harnessRoot, 'packages/core/agent-loop/tests/mock-adapter.ts'),
    'harness-mcp-bridge': join(harnessRoot, 'packages/mcp/mcp-client/src/tools.ts'),
    ...Object.fromEntries(['client/index.js', 'server/mcp.js', 'inMemory.js'].map(path => {
      const specifier = `@modelcontextprotocol/sdk/${path}`
      return [specifier, mcpRequire.resolve(specifier)]
    })),
  }
  await cp(join(pluginRoot, 'src'), join(scratch, 'src'), { recursive: true })
  await cp(join(pluginRoot, 'tests'), join(scratch, 'tests'), { recursive: true })
  await writeFile(join(scratch, 'vitest.config.ts'), `
import { defineConfig } from 'vitest/config'
import tsconfigPaths from 'vite-tsconfig-paths'
import { standardDecoratorPlugin } from '../../vitest.shared.ts'
export default defineConfig({
  plugins: [standardDecoratorPlugin(), tsconfigPaths({ projects: ['./tsconfig.base.json'] })],
  resolve: { alias: ${JSON.stringify(aliases)} },
  test: {
    include: [${JSON.stringify(`${relative(harnessRoot, scratch)}/tests/${mode === 'local' || mode === 'models' || mode === 'static-local' ? mode : mode ? 'gpt' : '{notice,pending,mcp,prompt,protocol-events,request,session-security,settings,static,text}'}.test.ts`)}],
    testTimeout: ${mode === 'login' ? 960000 : mode === 'live' || mode === 'models' ? 180000 : mode === 'local' || mode === 'static-local' ? 90000 : 10000},
    disableConsoleIntercept: ${Boolean(mode)},
    fileParallelism: false,
  },
})
`)
  const gptPrefix = process.env.PATRONUS_GPT_SCENARIO === 'dangerous' ? 'gpt-dangerous' : 'gpt-flow'
  const modelLevel = process.env.PATRONUS_MODEL_LEVEL
  if (mode === 'models' && !['l2', 'l3'].includes(modelLevel)) throw new Error('Set PATRONUS_MODEL_LEVEL=l2 or l3.')
  const reportPath = join(pluginRoot, mode === 'models' ? `${modelLevel}-flow.evidence.json` : mode === 'local' ? 'local-flow.evidence.json' : mode ? `${gptPrefix}.evidence.json` : 'pending-flow.evidence.json')
  const transcriptPath = join(pluginRoot, `${gptPrefix}.transcript.md`)
  if (!mode || mode === 'live' || mode === 'models') await rm(reportPath, { force: true })
  if (mode === 'live') await rm(transcriptPath, { force: true })
  const result = spawnSync(process.execPath, [
    join(harnessRoot, 'node_modules/vitest/vitest.mjs'), 'run',
    '--config', join(scratch, 'vitest.config.ts'),
    ...(mode ? ['--reporter', 'verbose'] : []),
  ], {
    cwd: harnessRoot,
    stdio: 'inherit',
    env: {
      ...process.env,
      PATRONUS_TEST_FIXTURES_ROOT: resolve(pluginRoot, '../../tests/fixtures/realistic'),
      PATRONUS_PROBE_REPORT: reportPath, PATRONUS_GPT_MODE: mode ?? '', PATRONUS_PROBE_TRANSCRIPT: transcriptPath,
    },
  })
  if (result.error) throw result.error
  if (result.status !== 0 && (!mode || mode === 'live' || mode === 'models')) await rm(reportPath, { force: true })
  process.exitCode = result.status ?? 1
} finally {
  await rm(scratch, { recursive: true, force: true })
}
