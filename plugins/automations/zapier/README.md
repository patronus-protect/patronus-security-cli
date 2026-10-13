# Patronus for Zapier

Zapier integration that adds the **Patronus → Guard Input** action: put it right before
your LLM step and it releases the exact text only after Patronus has checked it for
prompt injection and data leaks.

## Install

Open the **Patronus integration invite link** and accept it with your Zapier account.
After Zapier has published the integration, search for **Patronus** in the Zap editor.
The link is published in the [README](../README.md#get-patronus-for-your-platform).

## Set up

1. Create an API key in the [Patronus Control Plane](https://control.patronus.studio)
   with `scan:write` and `scan:read`.
2. Add **Patronus → Guard Input** to a Zap and choose **Sign in**. Paste the key.

## Use Guard Input

Map the exact prompt text into **RAG / LLM Input** and map the Guard's
**Protected Text** into your LLM step.

```text
Trigger → Patronus Guard Input → LLM action
Trigger → Code (retrieve + compose prompt) → Patronus Guard Input → LLM action
```

A blocked or unverified input stops the Zap at Guard Input; later steps are skipped and
the run shows as errored in Zap History. Do not add a path that sends the original text
to the LLM.

If your Zap starts with **Webhooks by Zapier**, use **Catch Raw Hook** and parse the
body in a Code step: the plain Catch Hook splits JSON-looking text (for example a chat
message containing `{"order": …}`) into sub-fields and leaves the original text empty.

Ready-made chatbot and RAG Zaps with step-by-step setup: [`examples/zapier`](../examples/zapier/README.md).

**Submit Scan** and **Get Scan Result** are diagnostic actions; they return raw scan
data and are not gates.

## For maintainers

The integration uses `zapier-platform-core` 19.1.0 on Node.js 22; the bundled entry is
`dist/index.js`, re-exported by `index.js` because Zapier's runtime loads the package
root. Register and push from a copy of this directory with a deploy key; a new
integration must start at version `1.0.0`. See [PUBLISHING.md](../PUBLISHING.md).
