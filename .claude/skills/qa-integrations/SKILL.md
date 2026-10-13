---
name: qa-integrations
description: Check that Patronus integrations work — host CLI drift against release pins, plugin manifests, local runtime, hosted API and MCP, OpenAPI contract and marketplace installs in a sandbox. Use as part of the QA run.
---

# Integration QA

1. Run `node qa/integrations.mjs`. It is read-only and checks:
   - the host CLI versions against `.github/release-host-versions.env`,
   - the plugin manifest versions,
   - the runtime probe and `integration <host> status`,
   - the published OpenAPI version against `contract/openapi-version.json`,
   - the hosted MCP `tools/list` for the QA account.
2. **Host drift**: if a host CLI is newer than its pin, the hook QA (`node qa/hooks.mjs`) already ran against the installed version in the same run.
   - If its host suite passed, propose a draft PR that bumps the pin in `.github/release-host-versions.env`.
   - If it failed, the existing hook finding explains why. Link both issues.
3. **OpenAPI drift**: diff the published `openapi.json` against `contract/` fixtures and the SDK request/response types. List new or changed endpoints and fields in the finding. A contract update is a draft-PR candidate only when it is mechanical; otherwise file an issue.
4. **Marketplace install, isolated**: verify that a new user can install the plugin from the marketplace without touching this machine's real config.
   - **Claude**: `CLAUDE_CONFIG_DIR=$(mktemp -d) claude plugin marketplace add <repo>` then `claude plugin install patronus-security@patronus-local` (both in the same temporary config dir). Check `claude plugin list --json`, then delete the directory.
   - **Codex**: use a temporary `CODEX_HOME` and `HOME` in the same way, with `patronus-security-scanner integration codex install`.
   - **Never** run install, enable or update against the real home directories.
5. **Hosted API plugin**: run `npm ci --ignore-scripts && npx playwright test` in `plugins/codex-api/` if its dependencies are present. Otherwise note that it was skipped.

Write any extra findings into `~/.patronus-qa/runs/<date>/integrations.json` (append to its `findings`, keeping the report shape).
