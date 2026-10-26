<h1 align="center">Patronus Security for Cursor</h1>

Patronus Runtime Protection adds security hooks to Cursor agent chats, in the Cursor IDE and in the `cursor-agent` CLI. It checks external text before the agent acts on it, while the scanner, policy and session state stay in the separately installed Patronus Security CLI.

## Protection level: partial

Cursor's hook API can replace only MCP results. Other outside text can be withheld or only flagged, and some never reaches a hook. Verified against the hook docs and the `cursor-agent` 2026.10.14 bundle:

| What reaches the agent | Cursor hook | Patronus behavior |
| --- | --- | --- |
| Your prompt | `beforeSubmitPrompt` | Scanned. Sensitive data blocks the prompt (`continue: false`); injection in your own prompt sends it with a warning. In the `cursor-agent` CLI only with `patronus-security-scanner integration cursor install` (user `hooks.json`): the interactive CLI skips this hook when it comes only from a plugin, and `cursor-agent -p` never runs it. |
| Shell command (before it runs) | `beforeShellExecution` | Checked. A command the model flags as risky (exfiltration, reverse shells, `curl … \| sh`, but also `rm -rf node_modules` or `git reset --hard`; routine commands such as `npm install` run) asks you; Patronus never blocks a command on its own. In `cursor-agent -p`, Cursor answers an ask itself: denied without `--force`, approved with `--force`. |
| File read by the Read tool | `beforeReadFile` | Scanned. A finding denies the read; the agent gets a receipt, or the masked file for personal data only. |
| MCP tool result | `postToolUse` | Scanned. A finding replaces the result (`updated_mcp_tool_output`). |
| Shell output | `postToolUse` | Scanned, **not withheld**: Cursor delivers it unchanged; Patronus adds a warning (`additional_context`). |
| Grep, web fetch, MCP resources, lint results, directory listings | none with content | **Not scanned.** Hooks receive only metadata (pattern, URL, length, counts). |
| Web search, Glob, codebase (semantic) search | none | **Not scanned.** These run on Cursor's servers. |
| Attached images, rules, `AGENTS.md`/`CLAUDE.md`, skills, `@`-context | none | **Not scanned.** Cursor loads them without `beforeReadFile`. |

PII disclosure (`patronus_reveal_pii`) is unavailable in Cursor: hooks cannot open an approval dialog for an MCP call (`ask` is ignored there). The agent continues with the masked result.

Use Claude Code or Codex where full result withholding is required.

### Claude Code hooks inside Cursor

Cursor also runs Claude Code hooks ("third-party hooks", so one hook script works in both tools): from `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json` and the Claude plugins enabled there. It passes them Cursor-format input, not Claude's. The Patronus Claude Code plugin recognizes Cursor input and stays out of the way; Cursor chats are protected by this integration. In the Cursor app, Settings → "Include Third-Party Plugins, Skills, and Other Configs" turns that loading off; the CLI always loads them.

## Install

```sh
patronus-security-scanner integration cursor install
```

The CLI downloads and verifies the matching release asset, copies the hook runtime to `~/.patronus-security-scanner/integrations/cursor`, and adds its entries to the user-level `~/.cursor/hooks.json` and `~/.cursor/mcp.json` (or `$CURSOR_CONFIG_DIR`). Other entries in those files are kept. Restart Cursor or start a new `cursor-agent` session afterwards. For installation by an agent, provide [`INSTALL.md`](INSTALL.md).

The directory also works as a Cursor plugin (`.cursor-plugin/plugin.json`, `hooks/hooks.json`, `mcp.json`), for example with `cursor-agent --plugin-dir plugins/cursor` or a team marketplace. Do not install it both ways; every hook would run twice.

## Hooks

| Cursor hook | Patronus behavior |
| --- | --- |
| `beforeSubmitPrompt` | Scans the prompt; handles `patronus on`, `patronus off` and `patronus status`. |
| `beforeShellExecution` | Checks the command line before it runs (ask). |
| `beforeReadFile` | Scans file content before the agent receives it. |
| `postToolUse` | Scans shell output and MCP `content[].text` blocks; answers Patronus' own MCP tools for this conversation. |
| `stop`, `sessionEnd` | Release the conversation's runtime state. |

Skills (`skills/`): `runtime` explains receipts, withheld reads, shell warnings and held commands; `scan` runs explicit audits; `patronus-setup` guides installation.

The Patronus MCP server (`patronus_check_result`, `patronus_read_redacted`, `patronus_scan`) runs without a conversation identity in Cursor; the `postToolUse` hook replaces its placeholder answer with the result for the current conversation.

## Fail-open behavior

Patronus is fail-open when scanning infrastructure is unavailable: the file read, tool result or prompt continues, with a degraded note where Cursor can show one. Completed findings are enforced on the surfaces listed above. An unavailable scan is never reported as approved.

## Degraded or inactive messages

Unless a message says the content was scanned locally, it was not scanned and remains unverified. Commands below are `patronus-security-scanner` subcommands.

| Message or reason | Cause | Fix |
| --- | --- | --- |
| `Patronus protection is inactive for this content` with `Check:` and `Repair:` commands | No scan result came back and no cause was reported: hooks disabled, scanner missing or broken. | `integration cursor status --format json`, then `integration cursor enable` |
| `Patronus is not signed in to the API`, `Your Patronus login has expired`, `The Patronus API rejected the saved login` | API scanning needs a valid login. If the message says `scanned locally instead`, the content was still scanned. | `auth login` |
| `Patronus API usage limit reached` | The account's usage or rate limit is exhausted. | `auth usage`; wait for the reset or raise the plan at https://control.patronus.studio/ |
| `api_timeout`, `api_unavailable`, `api_invalid_response`, `api_request_rejected` | The Patronus API did not answer, could not be reached or rejected the request. | Check connectivity and `auth status --check`, then retry |
| `broker_unavailable`, `runtime_start_failed`, `scanner_connection_lost`, `invalid_scanner_response`, `hook_input_invalid`, `hook_error` | The local integration (broker, scanner process or hook) failed. | `integration cursor status --format json`, then `integration cursor enable` |
| `runtime_version_mismatch` | The installed CLI and the hook runtime are different releases. | `maintenance update`, then `integration cursor update`, and restart Cursor |
| `configuration_unavailable` | The scanner configuration is invalid or unreadable. | `config print --format json` and fix the reported file |
| `scan_timeout`, `payload_too_large`, `unsupported_content`, `unsupported_payload`, `invalid_chunking` | The content is too large, too slow to scan or in an unsupported shape. | Raise `scan_timeout_ms` or `max_payload_bytes` ([configuration](https://github.com/patronus-protect/patronus-security-cli/blob/main/docs/configuration.md)) or treat the content as unverified |
| `Cursor cannot withhold shell output` | Expected: a shell result was flagged but Cursor delivers shell output unchanged. | Review the command output yourself; use Claude Code or Codex where withholding is required |

## Manage the integration

```sh
patronus-security-scanner integration cursor status
patronus-security-scanner integration cursor disable
patronus-security-scanner integration cursor update
patronus-security-scanner integration cursor uninstall
```

Requires Cursor with hooks (`cursor-agent` 2026.10.14 was used for the contract), Node.js 22.19 or newer, and the matching Patronus Security CLI release.

Licensed under Apache-2.0. The release archive includes `LICENSE` and `THIRD_PARTY_NOTICES.md`.
