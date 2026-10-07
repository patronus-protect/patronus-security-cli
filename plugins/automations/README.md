# Patronus automation plugins

Native API integrations for **n8n, Make, Dify, Zapier and Activepieces**. Every integration now has a **Guard Input** node/action/module for
`RAG or prompt text → Patronus → LLM`. Each integration authenticates with an account API key and calls
`https://control.patronus.studio/api/v1` directly. No Patronus CLI, scanner binary,
local model, daemon or CLI login is required on the automation host.

| Platform | Native integration | Setup |
| --- | --- | --- |
| n8n | Community node and password credential | [n8n](n8n/README.md) |
| Make | Custom app, basic API-key connection and Guard Input and four diagnostic modules | [Make](make/README.md) |
| Dify | Python tool provider and Guard Input workflow tool | [Dify](dify/README.md) |
| Zapier | Custom-auth integration and Guard Input action | [Zapier](zapier/README.md) |
| Activepieces | Piece, secret-text connection and Guard Input action | [Activepieces](activepieces/README.md) |

## Public availability

These integrations are Open Source under Apache-2.0. Native packages and their
release workflow are prepared, but no npm/marketplace publication or public
Make/Zapier installation link has been created by this work. See
[public distribution and owner setup](PUBLISHING.md) for the remaining steps.
Users should be able to install a release/package, enter their API key and connect
Guard Input; building code and assembling JSON are maintainer tasks.

## Authentication and actions

Create an account API key in the [Patronus Control Plane](https://control.patronus.studio)
with **`scan:write` and `scan:read`**. Enter the key only in the platform's
connection/credential field. It is sent as `Authorization: Bearer <key>`.
These integrations use API-key authentication, not the CLI's login session.
OAuth is not implemented because the public scan API specifies account API keys.

Submit Scan sends exactly one of `text`, `url` or `mcp_server_url` to `POST /scan`.
The API defaults to injection and DLP checks. URL/MCP inputs must be public HTTPS
endpoints; MCP scans inspect metadata without executing tools. Get Scan Result
uses `GET /scan/{job_id}` with the key belonging to the submitting account.
Document uploads and webhooks are outside this initial release.

Connection validation reads the reserved all-zero job ID. The API's authenticated
404 response confirms read access without sending user content or consuming scan
units. This checks **`scan:read` only**; `POST /scan` checks `scan:write`. n8n
exposes this as the Test Connection operation. The other hosts validate their
connection with the same probe. Unauthorized, quota, timeout and unavailable
responses do not count as successful authentication.

## Connect RAG / LLM input

Use **Guard Input**, which submits the scan, waits for asynchronous completion and
checks the full result inside the step. Connect the workflow as follows:

```text
Retriever / user input → template containing the exact LLM text → Guard Input → LLM
```

Map Guard Input's `text` into the LLM prompt. In Dify, map its native
`protected_text` variable instead. Do not map the retriever/source directly into
the LLM, and keep the platform's stop-on-error behavior. No separate polling loop
or allow/block filter is needed for Guard Input.

The gate requests injection and DLP with analysis up to L3 and checks completed job state, an allow decision,
no review verdict, complete extraction/coverage with matching document/page
counts, complete analysis without failures, and both requested categories'
authoritative clean classifications. It prefers `final_result` when present;
otherwise it accepts the current API's completed category format with model,
level and confidence. `benign` and native `safe` are clean labels. It does not re-threshold intermediate
model candidates. Missing/partial/degraded/failed/blocked/review results never
release text. The TypeScript/Python guards use a 10-second total budget; Make also enforces a 10-second release deadline and uses
at most 20 polling repeats at 500 ms. HTTP/timeout/quota errors stop the step.
Do not blindly retry a timed-out POST: a scan may already have started.

On success, the output contains the **exact original text** plus small receipt
metadata. It does not forward unscanned item fields, binary data, scan evidence or
source metadata. On failure there is no `text`/`protected_text` output. n8n's
Continue on Fail emits only a blocked/unverified error record; do not configure
an error fallback that feeds the original content into the LLM.

JSON-looking input remains one raw string. For structured RAG results, use the
platform's template/text aggregation step to assemble the exact text the LLM
will consume, then guard that assembled text. Media bytes are outside this text
gate. These are native workflow steps, not global platform interception hooks;
only the connected path is guarded.

For a live n8n smoke test, import [the example workflow](examples/n8n-guard-workflow.json),
select your Patronus API credential, and execute it. It previews the protected
LLM input without calling a model. Replace the source text with a known injection
fixture to verify that the preview step is not executed. The workflow is a
starter for installed-host QA, not a claim that your instance has already passed.

Submit Scan and Get Scan Result remain available for diagnostic/custom workflows.
They return scan data and are not pass-through gates. Make's diagnostic submission
body remains flat or enveloped as returned by the API; Guard Input handles its
single public text job internally and rejects unexpected job counts.

## Build, test and package

From the repository root (Node.js 24+ for development and Python 3.12+):

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
Activepieces, and copies the Python client unchanged into Dify's generated
`patronus_api_client/` directory. There is no dependency on publishing the Patronus
SDKs first. Make uses its native HTTP/IML definitions. Edit the SDK source rather
than generated copies. Packages, an unsigned `.difypkg`, the Make app-definition
ZIP and `SHA256SUMS` are written to `dist/`. CI repeats these checks and retains
the five packages as artifacts.

## Validation and remaining host checks

Local tests use the real platform SDKs and shared API response fixtures. They
check native registration/schema, request mapping, credentials, job IDs,
immediate/accepted/running/failed results, and sanitized API errors. Dify tests
also make real HTTP requests to a loopback mock server. No paid API scan or
account credential is needed for these tests.

Installed-host and live account tests still need the respective platform
instances/accounts. Before a public release, install each package in its target
host, create a dedicated test connection, run an allowed and a blocked fixture,
exercise asynchronous completion, revoked credentials and quota handling, and
confirm the workflow cannot bypass its result branch. Make's proprietary IML
runtime is not executed by the local checks. None of these integrations has been
published to a marketplace or deployed to an account by this change.

## Advisory fixes

The previous nine npm advisories are resolved without audit exclusions. The
development tree uses n8n-workflow 2.43.0 and patched axios 1.20.0, form-data 4.0.6,
lodash 4.18.1, nanoid 3.3.18, deepmerge-ts 8.0.2 and ai 6.0.301. The vulnerable
expr-eval 2.0.2 is replaced by the maintained expr-eval-fork 3.0.3.

The fixes persist in shipped packages: n8n has no runtime npm dependency;
Activepieces bundles its patched SDK tree and includes `dist/dependencies.json`
and third-party notices; Zapier bundles its patched runtime tree and includes its shrinkwrap; nested
installation cannot restore the vulnerable form-data version. Dify pins all 35 audited runtime packages in `requirements.txt`; its direct
SDK input lives in `requirements.in`. The development tree and standalone Zapier
runtime report zero npm advisories, and the Dify snapshot reports zero known
Python vulnerabilities as checked on 2026-10-07. CI runs both audits and fails on
new findings. Existing platform installations have their own dependencies; these
packages do not update the entire host.

## References

The [public Patronus OpenAPI contract](https://docs.patronus.studio/openapi.json)
is authoritative for API authentication and payloads. Platform definitions follow
the [n8n HTTP helper contract](https://github.com/n8n-io/n8n-docs/blob/main/docs/connect/create-nodes/build-your-node/reference/http-request-helpers.md),
[Make custom-app communication](https://developers.make.com/custom-apps-documentation/component-blocks/api),
[Dify plugin schemas](https://langgenius.github.io/dify-plugin-sdks/schema/),
[Zapier platform schema](https://github.com/zapier/zapier-platform/blob/main/packages/schema/docs/build/schema.md)
and [Activepieces authentication](https://www.activepieces.com/docs/build-pieces/piece-reference/authentication).

## Live API observation (2026-10-07)

A synthetic benign-text call through the authenticated Patronus API connector
returned `decision: allow` together with `completion: degraded` and an L3
`WorkerUnavailable`/HTTP 500 failure. Guard Input rejects that combination.
This observed API-worker problem must be resolved in the API service before a
healthy end-to-end release can be confirmed. It is separate from the dependency
fixes. Installed platform account tests are still pending.
