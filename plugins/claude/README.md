<p align="center">
  <a href="../../README.md"><img src="../../docs/img/providers/claude.svg" width="96" alt="Claude"></a>
</p>

<h1 align="center">Patronus Security for Claude Code</h1>

Patronus Runtime Protection adds native security gates to Claude Code chats. It checks external text before the next model turn while keeping the scanner, policy and session state in the separately installed Patronus Security CLI.

## Install

Select Claude Code during Patronus onboarding. The CLI detects Claude Code, downloads and verifies the matching release asset, registers the plugin and enables its hooks:

```sh
patronus-security-scanner onboarding
```

To add Claude Code later:

```sh
patronus-security-scanner integration claude install
```

For installation by an agent, provide [`INSTALL.md`](INSTALL.md).

Restart Claude Code after installation. Try:

> Check this repository with Patronus.

> Patronus status.

## What the hooks do

| Claude Code hook | Patronus behavior |
| --- | --- |
| `SessionStart` | Loads the plugin lifecycle for the chat. The scanner starts lazily with the first protected event. |
| `UserPromptSubmit` | Scans user-authored strings and text blocks before the model continues. |
| `PreToolUse` | Checks each `Bash` and `PowerShell` command line before it runs: a command the model flags as risky (exfiltration, reverse shells, `curl … \| sh`, but also `npm install` or `rm -rf node_modules`) asks you first; Patronus never blocks a command on its own. Also intercepts Patronus receipt-status, redaction and explicit scan operations, and asks you to approve a selective PII disclosure. Other tool requests are not scanned. |
| `PostToolUse` | Scans supported raw strings, text blocks, terminal output and text-file content returned by tools. |
| `PostToolUseFailure` | Scans the error text exposed by a failed tool result. |
| `SessionEnd` | Closes the session runtime and releases private state. |

MCP `content[].text` blocks use the separate MCP-result policy. JSON-looking text stays raw and ordered; images, paths, tool names, arguments, envelope keys, metadata and media bytes are outside the scanner input.

## Runtime flow

1. Claude Code exposes user input or a completed result to the installed hook.
2. The plugin extracts only the external text covered by the runtime contract.
3. The trusted Patronus Security CLI applies the configured policy for that host and surface.
4. Clean text continues. Findings replace the visible tool output with a bounded receipt or an available redacted result.
5. Pending results can be checked with the Patronus status tool without running the source action again.

Exact chat messages `patronus off`, `patronus on` and `patronus status` control protection for the current chat. They are recognized only at the user-input boundary.

## Fail-open behavior

Patronus is fail-open when scanning infrastructure is unavailable. Missing authentication, exhausted API usage, scanner startup errors, timeouts or an unavailable API do not prevent the requested tool from running. Claude Code receives the original result together with explicit degraded context and must treat it as unverified. An unavailable scan is never reported as approved.

A completed security finding is different: it is enforced. Prompt findings stop the model turn; result findings replace dangerous text. Fully covered PII/DLP-only results may continue through the separately retrieved masked view.

## Degraded or inactive messages

Unless a message says the content was scanned locally, it was not scanned and remains unverified. Scanner and integration failures name their public reason in parentheses. Commands below are `patronus-security-scanner` subcommands.

| Message or reason | Cause | Fix |
| --- | --- | --- |
| `Patronus protection is inactive for this content` with `Check:` and `Repair:` commands | No scan result came back and no cause was reported: the plugin is disabled or its scanner is missing or broken. | `integration claude status --format json`, then `integration claude enable`, then ask the agent to run `probe` |
| `Patronus is not signed in to the API`, `Your Patronus login has expired`, `The Patronus API rejected the saved login` | API scanning needs a valid login. If the message says `scanned locally instead`, the content was still scanned. | `auth login` |
| `Patronus API usage limit reached` | The account's usage or rate limit is exhausted; the message gives the seconds until the API is available again. | `auth usage`; wait for the reset or raise the plan at https://control.patronus.studio/ |
| `api_timeout`, `api_unavailable`, `api_invalid_response`, `api_request_rejected` | The Patronus API did not answer, could not be reached or rejected the request. | Check connectivity and `auth status --check`, then retry |
| `broker_unavailable`, `runtime_start_failed`, `scanner_connection_lost`, `invalid_scanner_response`, `hook_input_invalid`, `hook_error` | The local integration (broker, scanner process or hook) failed. | `integration claude status --format json`, then `integration claude enable`, then ask the agent to run `probe` |
| `runtime_version_mismatch` | The installed CLI and the plugin are different releases. | `maintenance update`, then `integration claude update`, and restart |
| `configuration_unavailable` | The scanner configuration is invalid or unreadable. | `config print --format json` and fix the reported file |
| `scan_timeout`, `payload_too_large`, `unsupported_content`, `unsupported_payload`, `invalid_chunking` | The content is too large, too slow to scan or in an unsupported shape. | Raise `scan_timeout_ms` or `max_payload_bytes` ([configuration](../../docs/configuration.md)) or treat the content as unverified |
| `local_scanner_error`, `scanner_crashed`, `incomplete_classification`, `invalid_classification`, `invalid_evidence_span` | The local scanner or a classifier failed on this content. | `assets prepare` for L2/L3 profiles; if it repeats, report it with `support-us` |
| `The Patronus remote audit ...` or `... static audit ...` | An explicitly requested URL, MCP or repository audit did not complete. | Follow the message: `auth login`, `auth usage`, a public HTTPS target, or retry later |

## Manage the integration

Open `patronus-security-scanner dashboard` to review activity and change policy. Restart Claude Code after installation or an update.

```sh
patronus-security-scanner integration claude status
patronus-security-scanner integration claude update
patronus-security-scanner integration claude uninstall
```

A supported Claude Code installation, Node.js 22.19 or newer, and the matching Patronus Security CLI release are required.

Licensed under Apache-2.0. The release archive includes `LICENSE` and `THIRD_PARTY_NOTICES.md`.
