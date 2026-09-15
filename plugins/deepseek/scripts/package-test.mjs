import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const harness = process.env.DSH_SOURCE_ROOT && resolve(process.env.DSH_SOURCE_ROOT)
const executable = process.env.PATRONUS_SCANNER_BIN
assert(harness, 'Set DSH_SOURCE_ROOT to the pinned, dependency-installed Harness checkout.')
assert(executable && isAbsolute(executable), 'Set PATRONUS_SCANNER_BIN to the absolute trusted local scanner executable.')
const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
const revision = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: harness, encoding: 'utf8' })
assert.equal(revision.stdout?.trim(), manifest.patronusProbe.harnessCommit)
await mkdir(join(harness, 'tmp'), { recursive: true })
const scratch = await mkdtemp(join(harness, 'tmp/patronus-package-'))
const packageRoot = join(scratch, 'package')
const env = { ...process.env, npm_config_cache: join(scratch, 'npm-cache') }
function run(command, args, cwd = packageRoot) {
  const result = spawnSync(command, args, { cwd, env, stdio: 'inherit', timeout: 180_000 })
  if (result.error) throw result.error
  assert.equal(result.status, 0, `${command} ${args.join(' ')} failed`)
}

try {
  for (const path of ['src', 'scripts/build.mjs', 'package.json', 'tsconfig.json', 'cordis.patch.yml', 'skills', 'README.md', 'INSTALL.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md']) {
    await cp(join(root, path), join(packageRoot, path), { recursive: true })
  }
  // Reuse the pinned host's dev tools without installing anything in this repository.
  const require = createRequire(join(harness, 'package.json'))
  const tsxRequire = createRequire(require.resolve('tsx/package.json'))
  await mkdir(join(packageRoot, 'node_modules'), { recursive: true })
  for (const [name, resolver] of [['esbuild', tsxRequire], ['js-yaml', require]]) {
    await symlink(dirname(resolver.resolve(`${name}/package.json`)), join(packageRoot, 'node_modules', name))
  }

  const ts = require('typescript')
  const native = ts.readConfigFile(join(harness, 'tsconfig.base.json'), ts.sys.readFile)
  const plugin = ts.readConfigFile(join(packageRoot, 'tsconfig.json'), ts.sys.readFile)
  assert(!native.error && !plugin.error, 'Cannot read TypeScript configuration.')
  const paths = Object.fromEntries(Object.entries(native.config.compilerOptions.paths)
    .map(([name, targets]) => [name, targets.map(path => resolve(harness, path))]))
  const parsed = ts.parseJsonConfigFileContent({
    ...plugin.config,
    compilerOptions: { ...plugin.config.compilerOptions, paths, typeRoots: [join(harness, 'node_modules/@types')], lib: ['ES2024'] },
  }, ts.sys, packageRoot)
  const program = ts.createProgram(parsed.fileNames, parsed.options)
  // Check every actual plugin source against native host types. Host implementations
  // have their own tsconfigs (notably non-strict legacy Cordis) and are not our roots.
  const diagnostics = [...parsed.errors, ...program.getOptionsDiagnostics(), ...program.getGlobalDiagnostics()]
  for (const file of parsed.fileNames) {
    const source = program.getSourceFile(file)
    assert(source, `Missing TypeScript source: ${file}`)
    diagnostics.push(...program.getSyntacticDiagnostics(source), ...program.getSemanticDiagnostics(source))
  }
  if (diagnostics.length) {
    throw new Error(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
      getCanonicalFileName: file => file, getCurrentDirectory: () => packageRoot, getNewLine: () => '\n',
    }))
  }
  console.log(`Typechecked ${parsed.fileNames.length} plugin source files against pinned native Harness types.`)
  run('npm', ['pack', '--pack-destination', scratch]) // prepack runs and validates the real build.
  const tarball = join(scratch, `${manifest.name.replace('@', '').replace('/', '-')}-${manifest.version}.tgz`)
  await cp(join(root, 'tests/packaging.test.ts'), join(scratch, 'packaging.test.ts'))
  await writeFile(join(scratch, 'vitest.config.ts'), `
import { defineConfig } from 'vitest/config'
import tsconfigPaths from 'vite-tsconfig-paths'
import { standardDecoratorPlugin } from '../../vitest.shared.ts'
export default defineConfig({
  plugins: [standardDecoratorPlugin(), tsconfigPaths({ projects: ['./tsconfig.base.json'] })],
  resolve: { alias: { 'harness-plugin-cli': ${JSON.stringify(join(harness, 'apps/cli/src/plugin.ts'))} } },
  test: { include: [${JSON.stringify(`${relative(harness, scratch)}/packaging.test.ts`)}], testTimeout: 120000, fileParallelism: false, disableConsoleIntercept: true },
})
`)
  Object.assign(env, { PATRONUS_PACKAGE_TARBALL: tarball, PATRONUS_PACKAGE_SCRATCH: scratch, DSH_SOURCE_ROOT: harness })
  run(process.execPath, [join(harness, 'node_modules/vitest/vitest.mjs'), 'run', '--config', join(scratch, 'vitest.config.ts'), '--reporter', 'verbose'], harness)
} finally {
  if (process.env.PATRONUS_PACKAGE_KEEP === '1') console.log(`Package test artifacts: ${scratch}`)
  else await rm(scratch, { recursive: true, force: true })
}
