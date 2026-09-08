import assert from 'node:assert/strict'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createRequire, isBuiltin } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
let esbuild
let yaml
try {
  esbuild = require('esbuild')
  yaml = require('js-yaml')
} catch {
  if (!process.env.DSH_SOURCE_ROOT) throw Error('Install plugin dev dependencies or set DSH_SOURCE_ROOT to the pinned local Harness checkout.')
  const host = createRequire(resolve(process.env.DSH_SOURCE_ROOT, 'package.json'))
  esbuild = createRequire(host.resolve('tsx/package.json'))('esbuild')
  yaml = host('js-yaml')
}

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const manifest = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'))
const patch = yaml.load(await readFile(resolve(root, 'cordis.patch.yml'), 'utf8'))
assert.equal(manifest.dsh?.bundle?.patch, './cordis.patch.yml')
assert.equal(manifest.exports['.'], './dist/index.js')
assert(patch.some(operation => operation.insert?.some(row => row.name === manifest.name)),
  'The bundle patch must mount this package.')
for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
  assert(!manifest.scripts[hook], 'Tarball installation must not require a build or binary download.')
}

const result = await esbuild.build({
  absWorkingDir: root,
  entryPoints: ['src/index.ts'],
  outfile: 'dist/index.js',
  bundle: true,
  packages: 'external',
  platform: 'node',
  target: 'node22',
  format: 'esm',
  tsconfig: resolve(root, 'tsconfig.json'),
  metafile: true,
  write: false,
})

// Keep host services external and reject accidental undeclared runtime imports.
const output = result.metafile.outputs['dist/index.js']
assert(output.exports.includes('apply') && output.exports.includes('inject'),
  'The artifact must export the native Cordis plugin entry points.')
for (const dependency of output.imports) {
  if (isBuiltin(dependency.path)) continue
  const name = dependency.path.startsWith('@')
    ? dependency.path.split('/').slice(0, 2).join('/')
    : dependency.path.split('/')[0]
  assert(dependency.external && (manifest.peerDependencies?.[name] || manifest.dependencies?.[name]),
    `Undeclared external dependency: ${dependency.path}`)
}
for (const source of Object.keys(result.metafile.inputs)) {
  assert(source.startsWith('src/') && !source.includes('node_modules'),
    `Only plugin source may be bundled: ${source}`)
}

await mkdir(resolve(root, 'dist'), { recursive: true })
await writeFile(resolve(root, 'dist/index.js'), result.outputFiles[0].contents)
console.log(`Built ${manifest.name}@${manifest.version}: dist/index.js (Harness dependencies external).`)
