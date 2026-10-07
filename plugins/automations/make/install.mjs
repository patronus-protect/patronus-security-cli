#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = new URL('.', import.meta.url);
const read = async path => JSON.parse(await readFile(new URL(path, root), 'utf8'));
const zones = ['eu1.make.com', 'eu2.make.com', 'us1.make.com', 'us2.make.com'];
export const makeModuleName = name => name.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());

export async function installMake({ appName = 'patronus', zone = 'eu1.make.com', token, apply = false, fetcher = fetch }) {
  if (!/^[a-z][a-z0-9_-]{1,63}$/.test(appName) || !zones.includes(zone)) throw new Error('Invalid app name or Make zone.');
  if (apply && (typeof token !== 'string' || !token.trim() || /[\r\n]/.test(token))) throw new Error('Set MAKE_API_TOKEN with sdk-apps:write access.');
  const app = await read('app.json');
  const calls = [];
  // Section bodies (base, connection and module sections) are sent as JSONC with PUT.
  async function request(method, path, body, contentType = 'application/json') {
    calls.push({ method, path, body });
    if (!apply) return path === '/sdk/apps' ? { app: { name: appName } } : { appConnection: { name: `${appName}-connection` } };
    const response = await fetcher(`https://${zone}/api/v2${path}`, {
      method, redirect: 'error', signal: AbortSignal.timeout(15_000),
      headers: { Authorization: `Token ${token}`, 'Content-Type': contentType, Accept: 'application/json' },
      body: Buffer.isBuffer(body) ? body : JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`Make ${method} ${path} failed (HTTP ${response.status}). No token or response body was logged. The app may be partially created.`);
    try { return await response.json(); }
    catch { throw new Error(`Make ${method} ${path} returned invalid JSON. Provisioning stopped.`); }
  }
  // The SDK Apps API takes the app fields at the top level and answers with { app }.
  const created = await request('POST', '/sdk/apps', {
    name: appName, label: 'Patronus', version: app.version, description: 'Guard RAG and LLM input through the Patronus API',
    language: 'en', theme: '#32b9fa', public: false, beta: true, manifestVersion: 1,
  });
  // Make appends a unique suffix to private app names (for example patronus-v2prbv).
  const installedName = created.app?.name;
  if (typeof installedName !== 'string' || !/^[a-z][a-z0-9_-]{1,63}$/.test(installedName)) throw new Error('Make did not return a valid app name.');
  appName = installedName;
  const prefix = `/sdk/apps/${appName}/${app.version}`;
  const section = async (path, file) => request('PUT', path, await read(file), 'application/jsonc');
  await section(`${prefix}/base`, 'base.json');
  // Patronus wolf/shield mark (512x512 PNG), shipped inside the Make archive.
  await request('PUT', `${prefix}/icon`, await readFile(new URL('assets/icon.png', root)), 'image/png');
  const connection = await request('POST', `/sdk/apps/${appName}/connections`, { type: 'basic', label: 'Patronus API' });
  const name = connection.appConnection?.name;
  if (typeof name !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(name)) throw new Error('Make did not return a valid connection name.');
  await section(`/sdk/apps/connections/${name}/parameters`, 'connections/patronus.parameters.json');
  await section(`/sdk/apps/connections/${name}/api`, 'connections/patronus.communication.json');
  for (const module of app.modules) {
    // Make module names must be alphanumeric: guard_input is installed as guardInput.
    const moduleName = makeModuleName(module.name);
    await request('POST', `${prefix}/modules`, {
      name: moduleName, typeId: 4, moduleInitMode: 'blank', label: module.label,
      description: module.name === 'guard_input' ? 'Release exact RAG/LLM text only after full Patronus approval' : module.label,
      connection: name,
    });
    // Inputs go to "expect" (mappable) so scenarios can pass text from earlier modules.
    for (const [target, source] of [['api', 'communication'], ['expect', 'parameters'], ['interface', 'interface']]) {
      await section(`${prefix}/modules/${moduleName}/${target}`, `modules/${module.name}.${source}.json`);
    }
  }
  return { applied: apply, appName, version: app.version, zone, calls };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const value = flag => args.includes(flag) ? args[args.indexOf(flag) + 1] : undefined;
  try {
    const result = await installMake({ appName: value('--app-name'), zone: value('--zone'), apply: args.includes('--apply'), token: process.env.MAKE_API_TOKEN });
    console.log(JSON.stringify(result, null, 2));
    if (!result.applied) console.log('Dry run only. Add --apply to create the app in your Make account.');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
