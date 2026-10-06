# Patronus Security hosted API plugin

This plugin connects to the authenticated Patronus API MCP at `https://control.patronus.studio/api/mcp`. Install the plugin and connect your Patronus account through the host's OAuth flow. Review account usage at [the account dashboard](https://control.patronus.studio).

Choose the exact text, supported document, URL or MCP server metadata to scan. Space/Page content requires the host's authorized access. The remote server cannot read local paths or inherit Space permissions; repository scans require explicit local file access or the separately installed CLI.

The interactive home provides scan forms, results and bounded polling. Space/Page and repository selection use host messages to request the necessary access. Account and installation links open through the host. Opening the home does not install software or verify runtime protection.

## Optional local runtime protection

Install the [local Codex plugin](../codex/README.md) separately for runtime protection. Its local receipt MCP and trusted hooks are required in addition to this hosted connection. Account tokens are not copied into the local receipt process. Review the hooks before enabling host trust and preserve your chosen processing provider.

## Packaging and validation

Run `node plugins/codex-api/package.mjs /absolute/output/path.zip` from the repository root. The explicit allowlist includes the manifests, skills, README and icon. It excludes local hooks, scanner binaries, server source and development files. Compatibility manifests are generated for Codex hosts that require the older entry point.

Browser tests run against an isolated mock host. Run `DSH_SOURCE_ROOT="$PWD/.harness" node plugins/codex-api/build-home.mjs` to prepare the shared home, then run `npm ci --ignore-scripts` and `npm test` in `plugins/codex-api/tests`. Mock tests do not prove installed-host OAuth or permission behavior; verify those in the target host before distributing a package.
