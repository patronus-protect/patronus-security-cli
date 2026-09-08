import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { root, bundle } from './builder.mjs'

const bytes = await bundle(resolve(root, 'src/cli.ts'), 'patronus.mjs')
for (const target of ['dist/patronus.mjs', '../codex/scripts/patronus.mjs', '../claude/scripts/patronus.mjs']) {
  const path = resolve(root, target)
  await mkdir(dirname(path), { recursive: true })
  await writeFile(path, bytes)
}
console.log('Built one shared native runtime for Codex and Claude (Node built-ins only).')
