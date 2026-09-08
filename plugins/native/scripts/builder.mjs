import { createRequire, isBuiltin } from 'node:module'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const root = fileURLToPath(new URL('..', import.meta.url))
const require = createRequire(import.meta.url)
let esbuild
try { esbuild = require('esbuild') }
catch {
  if (!process.env.DSH_SOURCE_ROOT) throw Error('Install native dev dependencies or set DSH_SOURCE_ROOT to the pinned local Harness checkout.')
  const host = createRequire(resolve(process.env.DSH_SOURCE_ROOT, 'package.json'))
  esbuild = createRequire(host.resolve('tsx/package.json'))('esbuild')
}
export async function bundle(entry, outfile) {
  const result = await esbuild.build({ entryPoints: [entry], outfile, bundle: true, platform: 'node', target: 'node22', format: 'esm', packages: 'external', metafile: true, write: false })
  for (const output of Object.values(result.metafile.outputs)) for (const dependency of output.imports) {
    if (dependency.external && !isBuiltin(dependency.path)) throw Error('Unexpected runtime dependency: ' + dependency.path)
  }
  return result.outputFiles[0].contents
}
