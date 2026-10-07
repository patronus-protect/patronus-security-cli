# Make submission

Shared texts: [README.md](README.md). Requirements:
[Make app review](https://developers.make.com/custom-apps-documentation/app-review) and
[prerequisites](https://developers.make.com/custom-apps-documentation/app-review/prerequisites).

## 1. App (created by `make/install.mjs`)

| Field | Value |
| --- | --- |
| Label | Patronus |
| Description | Guard RAG and LLM input through the Patronus API |
| Theme color | `#32b9fa` |
| Icon | `shared/assets/patronus-logo.png` (uploaded by the installer) |
| Language | English |

Run with the official Make organization:

```sh
MAKE_API_TOKEN=… node make/install.mjs --zone <zone> --apply
```

## 2. Modules

| Module | Label | Description |
| --- | --- | --- |
| `guardInput` | Guard Input | Release exact RAG/LLM text only after full Patronus approval |
| `scanText` | Submit Text Scan | Submit text for injection and DLP scanning |
| `scanUrl` | Submit URL Scan | Submit a public HTTPS page |
| `scanMcp` | Submit MCP Scan | Submit public MCP server metadata |
| `getScan` | Get Scan Result | Read a scan job and its findings |

## 3. Publish (invite link)

App page → **Publish** → copy the invite link and add it to the README table.

## 4. Review request — testing scenarios

Make asks for testing scenarios in the review form. Use the two example blueprints,
imported into the official organization and connected to the reviewer key:

1. **Patronus example – Chatbot** (`examples/make/chatbot.blueprint.json`):
   scenario input `message` → Guard Input → LLM log → Return output. Run with a clean
   message (released) and the injection test input (Guard Input errors, error handler
   records the rejection, the LLM step does not run).
2. **Patronus example – RAG** (`examples/make/rag.blueprint.json`):
   scenario input `question` → keyword retrieval over the example corpus → prompt →
   Guard Input → LLM log. `How many days before departure do I need to book a business
   flight?` is released; `How do new suppliers register during vendor onboarding?`
   retrieves a poisoned document and is blocked.

## Owner approval checklist

- [ ] App created in the official Patronus Make organization (not the test organization)
- [ ] Module help texts and sample outputs reviewed in the Make editor
- [ ] Both example scenarios imported and run once with the reviewer key
- [ ] App published (invite link) and review requested
