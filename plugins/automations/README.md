# Patronus for automation platforms

Stop prompt injection and data leaks **before** they reach your LLM. Patronus adds a
**Guard Input** step to n8n, Make, Zapier, Dify and Activepieces: put it between your
user input or retrieved RAG context and the LLM, and it releases the exact text only
when Patronus has fully checked it and found it clean.

```text
User message / retrieved documents → prompt → Patronus Guard Input → LLM
```

Open Source under Apache-2.0; the n8n node is MIT-licensed, as n8n requires for verified
nodes. No Patronus CLI, local model or extra service on your
automation host: the step calls the Patronus API with your API key.

## Get Patronus for your platform

| Platform | How to install | Guide |
| --- | --- | --- |
| **n8n** (self-hosted) | Settings → Community Nodes → Install → `n8n-nodes-patronus` | [n8n](n8n/README.md) |
| **n8n Cloud** | Search "Patronus" in the node panel once the node is verified by n8n | [n8n](n8n/README.md) |
| **Make** | Open the Patronus app invite link, then add the **Patronus** module to a scenario | [Make](make/README.md) |
| **Zapier** | Open the Patronus integration invite link, then add **Patronus → Guard Input** to a Zap | [Zapier](zapier/README.md) |
| **Dify** | Install the `.difypkg` from the latest GitHub release | [Dify](dify/README.md) |
| **Activepieces** | Upload the piece `.tgz` from the latest GitHub release | [Activepieces](activepieces/README.md) |

Make and Zapier invite links and the Patronus listings in the n8n, Make and Zapier
directories are added to this table as soon as each platform has published them; until
then the guides describe the current way to get each integration.

## Quick start

1. Create an API key in the [Patronus Control Plane](https://control.patronus.studio)
   with the **`scan:write`** and **`scan:read`** scopes.
2. Install Patronus on your platform (table above) and create a **Patronus API**
   connection with that key. Enter the key only in the platform's credential field.
3. Add **Guard Input** right before your LLM step and map the exact text your LLM will
   receive (the user message, or the prompt you assembled from retrieved documents).
4. Map Guard Input's **`text`** output (Dify: `protected_text`) into the LLM. Never map
   the original input or retrieved documents into the LLM directly.

Ready-made chatbot and RAG workflows for n8n, Make and Zapier, with clean and poisoned
test documents, are in [`examples/`](examples/README.md).

## What Guard Input guarantees

Guard Input submits the text with injection and DLP checks up to the deepest analysis
level and waits for the result inside the step. It releases the text only when the scan
completed, the decision is allow, extraction and coverage are complete, no analysis
failed or degraded, and both categories are clean. Otherwise the step stops with an
error and outputs no text, so the following LLM step does not run. Blocked, review,
incomplete, degraded, quota and timeout results all stop the step.

On success the output contains the exact original text plus a small receipt
(`patronus.status`, `patronus.job_ids`). It never forwards other input fields, binary
data or scan evidence. Keep the platform's stop-on-error behavior and do not add an
error fallback that feeds the original text into the LLM. Only the connected path is
guarded; these are workflow steps, not global platform hooks.

JSON-looking input stays one raw string. Media bytes are outside this text gate.

**Submit Scan** and **Get Scan Result** are diagnostic actions that return raw scan
data; they are not gates. Use Guard Input in front of an LLM.

## Privacy

The text you connect to Guard Input is sent to the Patronus API
(`https://control.patronus.studio/api/v1`) for scanning. The API key is stored by your
automation platform's credential store. Communication logs of the Make app mask the
Authorization header, request bodies and response bodies.

## For maintainers

- [Build, test, package and release](PUBLISHING.md), including the owner setup for npm,
  Make and Zapier.
- [Marketplace submission texts](listing/README.md) for n8n, Make and Zapier.
- [Verified platform runs](examples/README.md) with reproducible scripts.

The [public Patronus OpenAPI contract](https://docs.patronus.studio/openapi.json) is
authoritative for authentication and payloads.
