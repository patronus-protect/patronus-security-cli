# Build, release and publication

Maintainer guide for the Patronus automation integrations. End users install a
published package or listing; see the [README](README.md).

## Publication status

| Platform | Distribution | Status |
| --- | --- | --- |
| n8n self-hosted | npm package `n8n-nodes-patronus` | Package verified on n8n 2.42.4; npm publication pending (official npm account) |
| n8n Cloud | n8n-verified community node | Requires npm publication with provenance, then n8n verification |
| Make | Patronus custom app, invite link, then Make app review | Verified in a test organization; official app, invite link and review pending |
| Zapier | Private integration invite link, then public listing | Verified as private integration 1.0.0 in a test account; official integration and review pending |
| Dify | `.difypkg` release asset, later marketplace | Release asset prepared; not tested on a Dify host |
| Activepieces | `.tgz` release asset, later community catalogue | Release asset prepared; not tested on an Activepieces host |

Submission texts, review answers and test instructions are in [`listing/`](listing/README.md).

## Build, test and package

From the repository root (Node.js 24+ for development, Python 3.12+):

```sh
npm ci --prefix plugins/automations --ignore-scripts
npm test --prefix plugins/automations
npm run audit --prefix plugins/automations
python3 -m venv .venv  # only if the project has no venv yet
.venv/bin/python -m pip install -r plugins/automations/dify/requirements.txt
.venv/bin/python -m unittest discover -s plugins/automations/tests -p 'test_*.py' -v
.venv/bin/python plugins/automations/package.py
.venv/bin/python plugins/automations/verify_packages.py
```

The build bundles the repository's TypeScript API client into n8n, Zapier and
Activepieces and copies the Python client into Dify's generated
`patronus_api_client/` directory. Make uses native HTTP/IML definitions. Edit the SDK
source, not generated copies. Packages, an unsigned `.difypkg`, the Make app-definition
ZIP and `SHA256SUMS` are written to `dist/`; CI repeats these checks.

Local tests use the real platform SDKs and shared API response fixtures. Make's IML is
checked by an emulator in `tests/guard.test.cjs` that follows Make's observed runtime
semantics (loose `===`/`!==`, `createJSON()` returns no value for numbers). End-to-end
runs on the real platforms are scripted in [`examples/`](examples/README.md).

## Dependencies

The development tree and shipped packages report zero npm advisories and the Dify
snapshot zero known Python vulnerabilities (checked 2026-10-07); CI fails on new
findings. n8n has no runtime npm dependency; Activepieces and Zapier bundle their
patched runtime trees (Zapier ships its shrinkwrap). Overrides pin axios 1.20.0,
form-data 4.0.6, lodash 4.18.1, nanoid 3.3.18, deepmerge-ts 8.0.2 and ai 6.0.301, and
replace expr-eval with expr-eval-fork 3.0.3. Dify pins its runtime packages in
`requirements.txt`; its direct input is `requirements.in`.

## Release workflow

`Automation integration release` (`.github/workflows/automation-release.yml`) runs the
tests, dependency audits and offline package verification, checks all versions,
uploads packages and checksums and creates a **draft GitHub release**. npm publication
of n8n and Activepieces is optional and uses npm trusted publishing (OIDC) with
provenance; it is off by default. Make and Zapier are never published by CI.

## One-time owner setup (official accounts)

1. **GitHub:** create the `automation-releases` environment with required reviewers.
2. **npm:** create `n8n-nodes-patronus` and `@patronus-protect/piece-patronus` with the
   official npm account and configure trusted publishing for repository
   `patronus-protect/patronus-security-cli`, workflow `automation-release.yml` and
   environment `automation-releases` (npm ≥ 11.5.1). n8n accepts verified nodes only
   when they are published from GitHub Actions with provenance.
3. **Make:** with the official Make organization, run
   `node make/install.mjs --zone <zone> --apply` (needs `MAKE_API_TOKEN` with
   `sdk-apps:write`). It creates the app, connection, five modules and the app icon and
   prints the app name Make assigned. Test it with the Make example, then **Publish** the
   app to obtain its invite link and request the app review.
4. **Zapier:** with the official Zapier account and a deploy key, register and push the
   integration from a copy of `zapier/`. A new integration must start at version
   `1.0.0`. Upload `shared/assets/patronus-logo-256.png` as the logo in the developer
   portal, share the invite link and submit the integration for publishing.
5. Add the published invite links and listings to the README table.

## Platform notes found during verification

- **Zapier** loads `index.js` from the package root and ignores `package.json` `main`;
  `zapier/index.js` re-exports `dist/index.js`. Catch Hook expands JSON-looking string
  values, so the examples use Catch Raw Hook.
- **Make** private apps get a suffixed name and are addressed as `app#<name>`; module
  names must be alphanumeric; mappable inputs belong in `expect`; connection checks must
  answer 2xx; `POST /scenarios/{id}/run` returns no scenario outputs.
- **n8n 2.x** needs Node.js 24+; on Node.js 25 `isolated-vm` does not compile, so the
  local example installs n8n without native builds and uses the `legacy` expression
  engine.
