# Patronus for n8n

Native community node with a Patronus API credential. Requires Node.js 22+; the development SDK type-check runs on Node.js 24+;
tested against `n8n-workflow` 2.43.0. The package has no runtime npm dependencies. Scans call the account API through n8n's
`httpRequestWithAuthentication` helper. The key stays in n8n's credential store.

## Install

Build/package from [the parent directory](../README.md). In a self-hosted n8n
installation that permits community nodes, install the generated tarball in the
n8n user's nodes directory, then restart n8n:

```sh
cd ~/.n8n/nodes
npm install /absolute/path/to/n8n-nodes-patronus-0.1.1.tgz
```

Use the platform's [manual installation instructions](https://docs.n8n.io/integrations/community-nodes/installation-and-management/manual-installation.md)
for container paths and persistent volumes. This unpublished package is not
available as a verified n8n Cloud community node.

## Configure and use

1. Create a **Patronus API** credential; enter an account API key with `scan:write`
   and `scan:read` scopes in the masked API Key field.
2. Add Patronus and select **Test Connection**. It checks read access without a
   billable scan. Write access is checked when submitting.
3. Choose **Submit Scan**, a scan type, and Content. For text, map the exact source
   string. The node processes each input item and preserves item linkage.
4. For accepted jobs, use Wait, then **Get Scan Result** with the returned public
   job ID. Repeat with a bounded loop until terminal status.
5. Use an IF/Switch step to enforce your result policy before the LLM step. See
   [workflow behavior](../README.md#workflow-behavior).

By default an API error fails the node. n8n's Continue on Fail emits
`{"status":"unverified","error":"..."}`; that branch must not be treated as clean
input. These actions do not install automatic runtime hooks.

## Guard Input: connect directly before the LLM

Choose **Guard Input** and map the exact assembled RAG/prompt text into Content.
The step submits and polls internally, then releases only fully approved text.
Map the output `text` into the downstream LLM; in Dify use `protected_text`.
Blocked, review, incomplete, quota and timeout results stop the step without
returning the original input. Keep stop-on-error and do not use a source fallback.

The older Submit/Get actions are diagnostic operations. For the directly
connected protection path use Guard Input. See [the shared flow and test guide](../README.md#connect-rag--llm-input).

Import [the smoke-test workflow](../examples/n8n-guard-workflow.json) after installation and select the credential in Patronus Guard.
