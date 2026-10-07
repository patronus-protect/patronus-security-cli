# Patronus for n8n

Community node that adds **Patronus → Guard Input** to n8n: put it right before your
LLM node and it releases the exact text only after Patronus has checked it for prompt
injection and data leaks.

## Install

**Self-hosted n8n** (community nodes enabled):

1. Open **Settings → Community Nodes → Install**.
2. Enter `n8n-nodes-patronus`, confirm the risk notice and install.

Without the UI (for example in Docker images), install the package into the n8n user
folder and restart n8n:

```sh
cd ~/.n8n/nodes
npm install n8n-nodes-patronus
```

See n8n's [community node installation guide](https://docs.n8n.io/integrations/community-nodes/installation/)
for queue mode and persistent volumes.

**n8n Cloud:** the node becomes available in the node panel once n8n has verified it.

Requirements: Node.js 22+; verified with n8n 2.42.4. The package has no runtime npm
dependencies.

## Set up

1. Create an API key in the [Patronus Control Plane](https://control.patronus.studio)
   with `scan:write` and `scan:read`.
2. In n8n, create a **Patronus API** credential and paste the key. n8n tests the key
   with a minimal scan when you save the credential.

## Use Guard Input

Add **Patronus → Guard Input** directly before the LLM and map into **Content** the
exact text the LLM will receive. Then map the Guard's **`text`** output into the LLM.

```text
Chat Trigger → Patronus Guard Input → LLM
Question → retrieve documents → compose prompt → Patronus Guard Input → LLM
```

When the input is blocked or cannot be verified, the step fails and the LLM does not
run. To route rejections instead, enable **On Error → Continue** and branch on
`{{ $json.patronus?.status === 'allowed' }}`: the error item carries
`status: blocked | unverified` and never the original text. Do not add a fallback that
sends the original input to the LLM.

Ready-to-import chatbot and RAG workflows: [`examples/n8n`](../examples/n8n/README.md).

**Submit Scan** and **Get Scan Result** remain available as diagnostic operations; they
return raw scan data and are not gates. The node is also usable as a tool by n8n's AI
Agent, but a guard only protects the text you map into it.

## For maintainers

This package is a standard [`@n8n/node-cli`](https://docs.n8n.io/connect/create-nodes/build-your-node/using-the-n8n-node-tool)
project (`npm run build`, `npm run lint`, `npm run dev`) with no runtime dependencies,
as n8n's verification requires. The Patronus SDK and Guard logic are embedded in
`nodes/Patronus/lib/`, generated from `sdk/typescript` and `shared/` by
`plugins/automations/scripts/sync-n8n-lib.mjs`; edit the canonical sources and rerun
the script (the test suite fails when the copy is stale). The node calls the API
through n8n's `httpRequestWithAuthentication`, so the key stays in n8n's credential
store. Release steps: [PUBLISHING.md](../PUBLISHING.md).
