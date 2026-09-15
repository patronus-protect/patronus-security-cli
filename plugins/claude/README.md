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

### Let an agent install it

After you authorize changes to your Claude Code configuration, an agent may run
the integration command above and verify it with:

```sh
patronus-security-scanner integration claude status
```

The agent should use the CLI rather than editing Claude Code plugin files
directly. You must complete any browser login yourself and restart Claude Code
after installation. The agent must not request credentials in chat.

Restart Claude Code after installation. Try:

> Check this repository with Patronus.

> Patronus status.

## What the hooks do

| Claude Code hook | Patronus behavior |
| --- | --- |
| `SessionStart` | Loads the plugin lifecycle for the chat. The scanner starts lazily with the first protected event. |
| `UserPromptSubmit` | Scans user-authored strings and text blocks before the model continues. |
| `PreToolUse` | Intercepts only Patronus receipt-status, redaction and explicit scan operations. Ordinary tool requests are not scanned. |
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

## Manage the integration

Open `patronus-security-scanner dashboard` to review activity and change policy. Restart Claude Code after installation or an update.

```sh
patronus-security-scanner integration claude status
patronus-security-scanner integration claude update
patronus-security-scanner integration claude uninstall
```

A supported Claude Code installation, Node.js 22.19 or newer, and the matching Patronus Security CLI release are required.

Licensed under Apache-2.0. The release archive includes `LICENSE` and `THIRD_PARTY_NOTICES.md`.
