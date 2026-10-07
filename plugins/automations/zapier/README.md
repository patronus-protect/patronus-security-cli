# Patronus for Zapier

Native Zapier integration with custom API-key authentication and a Guard Input action plus diagnostic actions.
Uses `zapier-platform-core` 19.1.0 on Node.js 22. The bundled entry point is
`dist/index.js`; `.zapierapprc` explicitly includes `dist` in deployment builds.

Build/package from [the parent directory](../README.md). In this directory,
install the declared Zapier dependency and use your existing Zapier development
account and the [Zapier platform tooling](https://github.com/zapier/zapier-platform)
to register a private integration, validate it and push the build. The generated
`patronus-zapier-0.1.1.tgz` can also be extracted as a standalone app source tree.
Registration/deployment is not performed by the local build. No Patronus CLI is
used by the deployed actions.

Create a connection using a Patronus account API key with `scan:write` and
`scan:read`. The masked credential field is separate from action input. Connection
validation is a read-only missing-job probe and checks `scan:read`.

**Submit Scan** sends Text / Public HTTPS URL / Public MCP Server content and
returns an `id` (the first public job ID), submission status and all `jobs`.
**Get Scan Result** accepts a public job ID and returns its current state and
findings. Actions use `z.request`; the submit action does not poll within Zapier's
execution window. Use Delay and a bounded continuation/sub-Zap for running jobs,
and evaluate each returned job. A Filter/Paths step must enforce
[the completed-result policy](../README.md#workflow-behavior) before downstream
processing. If a job remains running, defer processing; a successful HTTP request
alone is not a clean scan.

The platform stores the API key. Actions suppress server-provided error messages
and expose only error kind, HTTP status, sanitized correlation/code fields and
retry timing. The patched core dependency tree is bundled and shrinkwrapped; see the parent README for the dependency audit.

## Guard Input: connect directly before the LLM

Choose **Guard Input** and map the exact assembled RAG/prompt text into Content.
The step submits and polls internally, then releases only fully approved text.
Map the output `text` into the downstream LLM; in Dify use `protected_text`.
Blocked, review, incomplete, quota and timeout results stop the step without
returning the original input. Keep stop-on-error and do not use a source fallback.

The older Submit/Get actions are diagnostic operations. For the directly
connected protection path use Guard Input. See [the shared flow and test guide](../README.md#connect-rag--llm-input).
