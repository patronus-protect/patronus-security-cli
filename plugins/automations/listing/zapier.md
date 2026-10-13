# Zapier submission

Shared texts: [README.md](README.md). Requirements:
[Zapier integration publishing requirements](https://docs.zapier.com/platform/publish/integration-publishing-requirements).

## 1. Integration settings (developer portal → Settings)

| Field | Value |
| --- | --- |
| Name | Patronus |
| Description | Guard RAG and chatbot input with Patronus: block prompt injection and data leaks before text reaches your LLM. |
| Homepage URL | https://patronus.studio |
| Logo | `shared/assets/patronus-logo-256.png` |
| Category | AI Safety (`ai-safety`) |
| Audience / role | Public (when submitting); role: employee of Patronus |

## 2. Authentication

| Field | Value |
| --- | --- |
| Type | Custom (API key) |
| Field label | API Key — help text: "Create a key with `scan:write` and `scan:read` at https://control.patronus.studio" |
| Connection label | `Patronus API` |

## 3. Actions (already defined in code)

| Key | Label | Description |
| --- | --- | --- |
| `guard_input` | Guard Input | Pass RAG or prompt text through Patronus before your LLM. Releases text only after full approval. |
| `submit_scan` | Submit Scan | Submit text, a public HTTPS page or public MCP metadata for injection and DLP scanning. |
| `get_scan` | Get Scan Result | Read a scan job. Check its status and findings before continuing. |

## 4. Sharing (pilot users, before publishing)

Developer portal → **Sharing** → copy the invite link and add it to the README table.

## 5. Publishing request — answers

| Question | Answer |
| --- | --- |
| What does your app do? | Long description in [README.md](README.md). |
| Who owns the API? | Patronus; the submitter is a Patronus employee. |
| Is the API publicly documented? | Yes: https://docs.patronus.studio/api-reference |
| How do users get credentials? | Self-service API keys at https://control.patronus.studio |
| Test account | Patronus account for `integration-testing@zapier.com` with its own API key, entered in the private test-credentials field. |
| Example Zap for review | Catch Raw Hook → Code (parse) → Patronus Guard Input → any action using **Protected Text**; see `examples/zapier/README.md`. |
| Help / support | team@patronus.studio, https://docs.patronus.studio/integrations/overview |
| Privacy policy / terms | https://patronus.studio/en/privacy-policy, https://patronus.studio/en/agb |

## Owner approval checklist

- [ ] Integration registered under the official Patronus Zapier account (not the test account)
- [ ] Version `1.0.0` pushed from CI or from a clean copy of `zapier/`
- [ ] Logo, description, homepage and category match this file
- [ ] Reviewer account created; key entered only in Zapier's private field
- [ ] Every action tested in a Zap that is turned on and has at least one successful run
- [ ] Reviewer test account registered with `integration-testing@zapier.com`, as the
      publishing requirements ask (no minimum number of triggers is required; Patronus
      ships actions only)
