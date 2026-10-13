import { readFile } from 'node:fs/promises';
const root = new URL('.', import.meta.url);
const read = async path => JSON.parse(await readFile(new URL(path, root), 'utf8'));
const version = (await read('package.json')).version;
if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('Invalid release version');
if (process.argv[2] && process.argv[2] !== version) throw new Error('Requested release does not match source version');
for (const file of ['n8n/package.json', 'activepieces/package.json', 'zapier/package.json', 'dify/manifest.yaml', 'package-lock.json', 'zapier/npm-shrinkwrap.json']) {
  if ((await read(file)).version !== version) throw new Error(`${file} version differs from ${version}`);
}
console.log(`Automation release ${version}: all source and lockfile versions match`);
