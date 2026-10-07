import { build } from 'esbuild';
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

const root = fileURLToPath(new URL('.', import.meta.url));
const bundle = (entry, outfile, external = []) => build({
  absWorkingDir: root, entryPoints: [entry], outfile, bundle: true,
  platform: 'node', target: 'node22', format: 'cjs', external, metafile: true,
});
await bundle('shared/client.ts', 'dist/client.cjs');
await bundle('shared/guard.ts', 'dist/guard.cjs');
await bundle('n8n/credentials/PatronusApi.credentials.ts', 'n8n/dist/credentials/PatronusApi.credentials.js', ['n8n-workflow']);
await bundle('n8n/nodes/Patronus/Patronus.node.ts', 'n8n/dist/nodes/Patronus/Patronus.node.js', ['n8n-workflow']);
// Brand mark from the Patronus desktop app (shared/assets/patronus-logo.png, 512x512, transparent).
await cp(`${root}shared/assets/patronus-logo.png`, `${root}n8n/dist/nodes/Patronus/patronus.png`);
await cp(`${root}shared/assets/patronus-logo.png`, `${root}n8n/dist/credentials/patronus.png`);
// Bundle the patched SDK tree: npm ignores a nested package's overrides at installation.
const piece = await bundle('activepieces/src/index.ts', 'activepieces/dist/index.js');
const packages = new Map();
for (const input of Object.keys(piece.metafile.inputs).filter(path => path.includes('node_modules/'))) {
  let directory = dirname(join(root, input));
  while (directory.startsWith(root)) {
    try {
      const manifest = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8'));
      if (!manifest.name || !manifest.version) { directory = dirname(directory); continue; }
      packages.set(`${manifest.name}@${manifest.version}`, { directory, name: manifest.name, version: manifest.version, license: manifest.license });
      break;
    } catch { directory = dirname(directory); }
  }
}
const components = [...packages.values()].sort((a, b) => a.name.localeCompare(b.name));
await writeFile(`${root}activepieces/dist/dependencies.json`, JSON.stringify({
  source_lock_sha256: createHash('sha256').update(await readFile(`${root}package-lock.json`)).digest('hex'),
  packages: components.map(({ directory, ...component }) => component),
}, null, 2) + '\n');
let notices = 'Bundled dependencies of the Patronus Activepieces piece.\n\n';
for (const component of components) {
  notices += `${component.name}@${component.version} (${component.license ?? 'See upstream license'})\n`;
  for (const name of ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'license', 'license.md']) {
    try { notices += await readFile(join(component.directory, name), 'utf8'); break; }
    catch {}
  }
  notices += '\n\n';
}
await writeFile(`${root}activepieces/dist/THIRD_PARTY_NOTICES.txt`, notices);
await bundle('zapier/index.cjs', 'zapier/dist/index.js', ['zapier-platform-core']);
await rm(`${root}dify/patronus_api_client`, { recursive: true, force: true });
await cp(new URL('../../sdk/python/src/patronus_api_client/', import.meta.url), `${root}dify/patronus_api_client`, {
  recursive: true, filter: source => !source.includes('__pycache__') && !source.endsWith('.pyc'),
});
for (const platform of ['n8n', 'activepieces', 'zapier', 'dify', 'make']) {
  await cp(new URL('../../LICENSE', import.meta.url), `${root}${platform}/LICENSE`);
}
// The generated copy is always sourced from the contract-tested Python SDK.
await mkdir(`${root}dist`, { recursive: true });
const contract = JSON.parse(await readFile(new URL('../../contract/openapi-version.json', import.meta.url), 'utf8'));
await writeFile(`${root}dist/contract.json`, JSON.stringify(contract, null, 2) + '\n');
