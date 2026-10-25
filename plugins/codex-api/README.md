# Patronus Security hosted API plugin

This plugin connects to the authenticated Patronus API MCP at `https://control.patronus.studio/api/mcp`. Install the plugin and connect your Patronus account through the host's OAuth flow. Review account usage at [the account dashboard](https://control.patronus.studio).

Choose the exact text, supported document, URL or MCP server metadata to scan. Space/Page content requires the host's authorized access. The remote server cannot read local paths or inherit Space permissions; repository scans require explicit local file access or the separately installed CLI.

In Web, scan selected text on request through chat or the home’s text field. This package does not automatically check every prompt or tool result before it reaches the model. Files attached to a Space, Page or Dot require actual host access to their contents; scanning the surrounding Page text or a file link does not scan the attachment. Dot file access is separate from runtime hooks. See [OpenAI’s hook compatibility](https://learn.chatgpt.com/docs/hooks#managed-hooks-from-requirementstoml) for managed cloud hooks.

The interactive home provides scan forms, results and bounded polling. Space/Page and repository selection use host messages to request the necessary access. Account and installation links open through the host. Opening the home does not install software or verify runtime protection.

## Optional local runtime protection

Install the [full desktop Codex plugin](https://github.com/patronus-protect/patronus-security-cli/blob/main/plugins/codex/README.md) for runtime protection in supported locally orchestrated chats. It already includes the hosted API connection alongside its local receipt MCP and hooks; a second API-only installation is not required. Account tokens are not copied into the local receipt process. Review the hooks before enabling host trust and preserve your chosen processing provider.

## Packaging and validation

Run `node plugins/codex-api/package.mjs /absolute/output/path.zip` from the repository root. The explicit allowlist includes the manifests, skills, README and icon. It excludes local hooks, scanner binaries, server source and development files. Compatibility manifests are generated for Codex hosts that require the older entry point.

Browser tests run against an isolated mock host. Run `DSH_SOURCE_ROOT="$PWD/.harness" node plugins/codex-api/build-home.mjs` to prepare the shared home, then run `npm ci --ignore-scripts` and `npm test` in `plugins/codex-api/tests`. Mock tests do not prove installed-host OAuth or permission behavior; verify those in the target host before distributing a package.

For public submission, use the five positive and three negative cases in `extensions.com.openai.review.test_cases` in `plugin.json`. Release notes are included in `extensions.com.openai.publication.release_notes`. Run the cases with a dedicated reviewer account in the installed host, then provide the accessible walkthrough recording and reviewer access through the submission portal. Keep credentials out of the package. See [OpenAI's submission guide](https://developers.openai.com/plugins/deploy/submission).
