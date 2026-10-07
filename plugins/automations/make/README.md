# Patronus for Make

Make app that adds the **Patronus → Guard Input** module: put it right before your LLM
module and it releases the exact text only after Patronus has checked it for prompt
injection and data leaks.

## Install

Open the **Patronus app invite link** and install the app into your Make organization.
Once Make has reviewed the app, it is also available to every Make user directly in the
module search. The link is published in the [README](../README.md#get-patronus-for-your-platform).

## Set up

1. Create an API key in the [Patronus Control Plane](https://control.patronus.studio)
   with `scan:write` and `scan:read`.
2. Add any Patronus module to a scenario and choose **Create a connection**. Paste the
   key into **API Key**. Make checks the key with a minimal scan.

## Use Guard Input

Add **Patronus → Guard Input** directly before your LLM module, map the exact prompt
text into **RAG / LLM Input** and map the Guard's **Protected Text** into the LLM.

```text
Trigger → Patronus Guard Input → LLM module
Trigger → retrieve documents → Text aggregator / Set variable (prompt) → Patronus Guard Input → LLM module
```

A blocked or unverified input raises an error on Guard Input and no later module runs.
To handle rejections explicitly, add an error handler route to Guard Input (for example
log the rejection, then **Ignore**). Never route the original text to the LLM from the
error handler.

Ready-to-import chatbot and RAG blueprints: [`examples/make`](../examples/make/README.md).

**Submit Text / URL / MCP Scan** and **Get Scan Result** are diagnostic modules; they
return raw scan data and are not gates.

## For maintainers

`install.mjs` provisions the app in the publisher's Make organization through the SDK
Apps API (dry run by default; `--apply` with `MAKE_API_TOKEN` creates the app, its
connection, five modules and the icon). It is publisher tooling, not end-user setup.
See [PUBLISHING.md](../PUBLISHING.md). Guard Input uses only native IML built-ins; the
base masks Authorization, request bodies and response bodies in communication logs.
