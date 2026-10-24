#!/usr/bin/env node
// `npm audit --audit-level=low` with a short list of reviewed exceptions. An exception covers
// one advisory at one exact installed package version and path; anything else still fails.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const exceptions = [
  // zod 3.25.x ships the zod 4 core under `zod/v4`, which n8n-workflow imports. No patched
  // 3.x exists, and current n8n-workflow / @n8n/expression-runtime still pin 3.25.76.
  // Dev-only here: n8n-workflow is a peer the n8n host provides at runtime, and no shipped
  // bundle contains this copy (Activepieces bundles its own zod, overridden to 4.6.7).
  // Remove once n8n moves to zod >= 4.6.6.
  { advisory: 'GHSA-mrhx-c7xc-m3w5', path: 'node_modules/zod', version: '3.25.76' },
];

let report;
try { report = execFileSync('npm', ['audit', '--json', '--audit-level=low'], { cwd: root, encoding: 'utf8' }); }
catch (error) { report = error.stdout; }
const { vulnerabilities = {} } = JSON.parse(report);
const lock = JSON.parse(readFileSync(new URL('package-lock.json', root), 'utf8')).packages;

const excepted = (name, vulnerability) => vulnerability.via.every(via => {
  // A package that is only vulnerable through other packages is fine when those are.
  if (typeof via === 'string') return via !== name && vulnerabilities[via] !== undefined && excepted(via, vulnerabilities[via]);
  return vulnerability.nodes.every(path => exceptions.some(item =>
    via.url?.endsWith(`/${item.advisory}`) && item.path === path && lock[path]?.version === item.version));
});

const open = Object.entries(vulnerabilities).filter(([name, vulnerability]) => !excepted(name, vulnerability));
for (const [name, vulnerability] of Object.entries(vulnerabilities)) {
  const advisories = vulnerability.via.map(via => typeof via === 'string' ? `via ${via}` : via.url).join(', ');
  process.stdout.write(`${open.some(([other]) => other === name) ? 'FAIL' : 'excepted'} ${name} (${vulnerability.severity}): ${advisories}\n`);
}
if (open.length) process.exit(1);
process.stdout.write(`npm audit: no open advisories (${Object.keys(vulnerabilities).length} covered by reviewed exceptions).\n`);
