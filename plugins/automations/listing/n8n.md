# n8n submission

Shared texts: [README.md](README.md). Requirements:
[Submit community nodes](https://docs.n8n.io/connect/create-nodes/deploy-your-node/submit-community-nodes)
and [verification guidelines](https://docs.n8n.io/connect/create-nodes/build-your-node/reference/verification-guidelines).

## 1. npm package

| Field | Value |
| --- | --- |
| Package | `n8n-nodes-patronus` |
| Keywords | `n8n-community-node-package`, `patronus`, `security` |
| Repository | `patronus-protect/patronus-security-cli`, directory `plugins/automations/n8n` |
| License | MIT (n8n verification requirement; the rest of the repository is Apache-2.0) |
| Runtime dependencies | none |

Publishing: since 1 May 2026 n8n verifies only packages published from GitHub Actions
with an npm provenance statement. Publish through `automation-release.yml` with npm
trusted publishing (see [PUBLISHING.md](../PUBLISHING.md)); do not publish from a laptop.

## 2. Verification submission (n8n Creator Portal)

| Field | Value |
| --- | --- |
| Node name | Patronus |
| npm package | `n8n-nodes-patronus` |
| Description | Short description from [README.md](README.md) |
| Documentation | https://github.com/patronus-protect/patronus-security-cli/tree/main/plugins/automations/n8n |
| Credentials for review | Reviewer account and key, entered only in the portal's private field |
| Example workflows | `examples/n8n/chatbot.workflow.json`, `examples/n8n/rag.workflow.json` |

## Owner approval checklist

- [ ] npm package created under the official Patronus npm account; trusted publisher configured
- [x] License of `n8n-nodes-patronus` set to MIT (verification requirement)
- [ ] Package built and linted with `@n8n/node-cli` and passes `npx @n8n/scan-community-package`
- [ ] First version published from CI with provenance
- [ ] Submission entered in the Creator Portal with the reviewer account
