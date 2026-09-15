<p align="center">
  <a href="../../README.md"><img src="../../docs/img/providers/codex-app.png" width="96" alt="Codex app"></a>
</p>

<h1 align="center">Patronus Security for Codex</h1>

Patronus Runtime Protection adds native security gates to Codex chats. It checks external text before the next model turn while keeping the scanner, policy and session state in the separately installed Patronus Security CLI.

## Install

Select Codex during Patronus onboarding. The CLI detects Codex, downloads and verifies the matching release asset, registers the plugin and prepares its hooks:

```sh
patronus-security-scanner onboarding
```

To add Codex later:

```sh
patronus-security-scanner integration codex install
```

Start a new Codex task after installation. Try:

> Check this repository with Patronus.

> Patronus status.

## What the hooks do

| Codex hook | Patronus behavior |
| --- | --- |
| `SessionStart` | Loads the plugin lifecycle for the task. The scanner starts lazily with the first protected event. |
| `UserPromptSubmit` | Scans every user-authored text value before the model continues. |
| `PreToolUse` | Intercepts only Patronus receipt-status, redaction and explicit scan operations. Ordinary tool requests are not scanned. |
| `PostToolUse` | Scans raw text returned by tools. MCP tool results use the separate MCP-result policy. |
| `Stop` | Closes the session runtime and releases private state. |

Text blocks remain in their original order. JSON-looking text is scanned as raw text. Images, audio, paths, tool names, arguments, envelope keys and metadata are not sent to the scanner.

## Runtime flow

1. Codex exposes user input or a completed tool result to the installed hook.
2. The plugin extracts only the external text covered by the runtime contract.
3. The trusted Patronus Security CLI applies the configured policy for that host and surface.
4. Clean text continues. Findings produce a bounded receipt or an available redacted result instead of exposing a dangerous original.
5. Pending results can be checked with the Patronus status tool without running the source action again.

Exact chat messages `patronus off`, `patronus on` and `patronus status` control protection for the current task. They are recognized only at the user-input boundary.

## Fail-open behavior

Patronus is fail-open when scanning infrastructure is unavailable. Missing authentication, exhausted API usage, scanner startup errors, timeouts or an unavailable API do not prevent the requested tool from running. Codex receives the original result together with explicit degraded context and must treat it as unverified. An unavailable scan is never reported as approved.

A completed security finding is different: it is enforced. Prompt findings stop the model turn; result findings withhold the dangerous original. Fully covered PII/DLP-only results may continue through the separately retrieved masked view.

## Manage the integration

Open `patronus-security-scanner dashboard` to review activity and change policy. After an update, restart Codex so new tasks load the current hooks and skills.

```sh
patronus-security-scanner integration codex status
patronus-security-scanner integration codex update
patronus-security-scanner integration codex uninstall
```

A supported Codex installation, Node.js 22.19 or newer, and the matching Patronus Security CLI release are required.

Licensed under Apache-2.0. The release archive includes `LICENSE` and `THIRD_PARTY_NOTICES.md`.
