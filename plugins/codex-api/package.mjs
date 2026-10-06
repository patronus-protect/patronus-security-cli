import { mkdtemp, mkdir, copyFile, readFile, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

// Deliberate allowlist: never bundle local hooks, server source or credentials.
const root = fileURLToPath(new URL('.', import.meta.url))
const files = ['plugin.json', 'mcp.json', '.codex-plugin/plugin.json', '.mcp.json', 'README.md', 'assets/icon.png',
  ...['patronus-api-setup', 'patronus-api-scan', 'patronus-local-runtime'].map(name => `skills/${name}/SKILL.md`)]
const plugin = JSON.parse(await readFile(join(root, 'plugin.json'), 'utf8'))
const mcp = JSON.parse(await readFile(join(root, 'mcp.json'), 'utf8'))
if (plugin.hooks || plugin.apps || JSON.stringify(mcp).includes('"command"')) throw Error('Public package must use hosted MCP without hooks or app references.')
if (mcp.mcpServers['patronus-api'].url !== 'https://control.patronus.studio/api/mcp') throw Error('Unexpected MCP endpoint.')
// Older installed Codex hosts still require the compatibility entry point.
const { $schema, extensions, ...identity } = plugin
await mkdir(join(root, '.codex-plugin'), { recursive: true })
await writeFile(join(root, '.codex-plugin/plugin.json'), JSON.stringify({ ...identity, ...extensions['com.openai'], skills: './skills/', mcpServers: './.mcp.json' }, null, 2) + '\n')
await writeFile(join(root, '.mcp.json'), JSON.stringify({ mcpServers: { 'patronus-api': { url: mcp.mcpServers['patronus-api'].url } } }, null, 2) + '\n')
const output = resolve(process.argv[2] || join(tmpdir(), 'patronus-security-api-0.1.2.zip'))
const stage = await mkdtemp(join(tmpdir(), 'patronus-public-plugin-'))
try {
  for (const name of files) {
    const target = join(stage, name)
    await mkdir(resolve(target, '..'), { recursive: true })
    await copyFile(join(root, name), target)
  }
  await rm(output, { force: true })
  const result = spawnSync('zip', ['-q', '-X', output, ...files], { cwd: stage, encoding: 'utf8' })
  if (result.status !== 0) throw Error(result.stderr || 'ZIP creation failed; install the zip utility.')
  console.log(output)
} finally { await rm(stage, { recursive: true, force: true }) }
