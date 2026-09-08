import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const nativeRoot = fileURLToPath(new URL('..', import.meta.url))
const harness = process.env.DSH_SOURCE_ROOT && resolve(process.env.DSH_SOURCE_ROOT)
assert(harness, 'Set DSH_SOURCE_ROOT to the pinned Harness checkout for the shared core type contracts.')
const ts = createRequire(join(harness, 'package.json'))('typescript')
const native = ts.readConfigFile(join(harness, 'tsconfig.base.json'), ts.sys.readFile)
assert(!native.error, 'Cannot read host TypeScript configuration.')
const paths = Object.fromEntries(Object.entries(native.config.compilerOptions.paths)
  .map(([name, targets]) => [name, targets.map(path => resolve(harness, path))]))
for (const root of [nativeRoot, resolve(nativeRoot, '../deepseek')]) {
  const plugin = ts.readConfigFile(join(root, 'tsconfig.json'), ts.sys.readFile)
  assert(!plugin.error, 'Cannot read plugin TypeScript configuration.')
  const parsed = ts.parseJsonConfigFileContent({
    ...plugin.config,
    compilerOptions: { ...plugin.config.compilerOptions, paths, typeRoots: [join(harness, 'node_modules/@types')] },
  }, ts.sys, root)
  const program = ts.createProgram(parsed.fileNames, parsed.options)
  const diagnostics = [...parsed.errors, ...program.getOptionsDiagnostics(), ...program.getGlobalDiagnostics()]
  // The host owns its implementations; check our roots and the reused local core.
  const sources = program.getSourceFiles().filter(file => file.fileName.startsWith(root) || file.fileName.startsWith(resolve(root, '../deepseek/src') + '/'))
  for (const source of sources) diagnostics.push(...program.getSyntacticDiagnostics(source), ...program.getSemanticDiagnostics(source))
  if (diagnostics.length) {
    process.stderr.write(ts.formatDiagnostics(diagnostics, {
      getCanonicalFileName: file => file, getCurrentDirectory: () => root, getNewLine: () => '\n',
    }))
    process.exitCode = 1
  } else console.log(`Typechecked ${sources.length} files in ${root}.`)
}
