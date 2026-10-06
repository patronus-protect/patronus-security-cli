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

For installation by an agent, provide [`INSTALL.md`](INSTALL.md).

Start a new Codex task after installation. Try:

> Check this repository with Patronus.

> Patronus status.

## What the hooks do

| Codex hook | Patronus behavior |
| --- | --- |
| `SessionStart` | Validates lifecycle input and reads protection settings so lifecycle failures can be reported. The scanner starts lazily with the first protected event; startup is not proof of an active scan. |
| `UserPromptSubmit` | Checks user-authored text before model delivery to catch sensitive data and warn about pasted instructions. Also recognizes exact chat protection commands. User-prompt PII detection is off by default. |
| `PreToolUse` | Attributes Patronus receipt-status, redaction and explicit scan operations to the current chat because the Codex MCP process has no chat identity. Ordinary tool requests are not scanned. |
| `PostToolUse` | Gates raw tool-result text before model delivery to enforce findings without rerunning the tool. MCP text uses the separate MCP-result policy; Patronus receipts are not rescanned. |
| `Stop` | Releases the turn's private broker runtime state. Codex emits this event at turn end, not only when the chat closes. |

`hooks/hooks.json` includes a top-level description and a `statusMessage` for each handler. Codex documents these fields; a persistent per-handler description is not documented. Changing hook definitions requires a new trust review. Review the updated hooks and start a new task after installation or update.

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

A completed security finding is different: it is enforced. User prompts with only injection/threat findings continue with a warning to treat pasted instructions as data; sensitive-data findings block the prompt. Result findings withhold the dangerous original. Fully covered PII/DLP-only results may continue through the separately retrieved masked view.

## Public directory, plugin UI and Spaces

As of October 1, 2026, OpenAI's public submission flow rejects packages containing lifecycle hooks. This runtime package also uses a local stdio MCP server; regular public MCP submissions require a remote HTTPS endpoint. Local/repo marketplace installation does not establish public submission readiness.

The Codex MCP server includes `patronus_open_home` and the bundled `ui://patronus/home` MCP Apps resource. It declares OpenAI global/sidebar and thread/panel entrypoints. The home provides setup, dashboard and explicit scan starters through user-initiated chat messages, with a readable fallback when the host bridge is unavailable. It does not verify protection status or embed the local dashboard. Sidebar visibility depends on the host's MCP Extensions support and must be verified after installation.

Local Codex chats use the hooks above. Cloud-orchestrated Work does not support plugin command hooks, even with local execution. Enterprise-managed remote MCP hooks are a separate admin integration. No dedicated Space/Page-content-change hook was identified in the published hook reference; supported tool-result hooks cover content only when the host actually exposes it through that boundary.

Space data access is a separate capability: a host's authorized Pages tools can read Pages, references and change history. This local Patronus MCP server does not automatically inherit those permissions or provide a direct Space connection. Absence of a Page-change hook does not mean the agent cannot read authorized Page data.

Scheduled tasks (routines) can use skills and plugins. A scoped workflow could periodically read authorized Page changes and request a scan, but this package does not yet implement that Page-check workflow or configure a routine on installation. Scheduled inspection does not enforce a pre-model boundary. Locally orchestrated tasks can use trusted local hooks; cloud-orchestrated tasks cannot use this package's command hooks. See [scheduled tasks](https://learn.chatgpt.com/docs/automations) for task/plugin availability and execution requirements.

See OpenAI's [submission requirements](https://developers.openai.com/plugins/deploy/submission), [sidebar extension guide](https://developers.openai.com/plugins/build/extensions#sidebar-apps), and [hook reference](https://learn.chatgpt.com/docs/hooks) for the current distribution and host boundaries.

## Manage the integration

Open `patronus-security-scanner dashboard` to review activity and change policy. After an update, restart Codex so new tasks load the current hooks and skills.

```sh
patronus-security-scanner integration codex status
patronus-security-scanner integration codex update
patronus-security-scanner integration codex uninstall
```

A supported Codex installation, Node.js 22.19 or newer, and the matching Patronus Security CLI release are required.

Licensed under Apache-2.0. The release archive includes `LICENSE` and `THIRD_PARTY_NOTICES.md`.
# Distribution variants

The hosted API candidate is in [`../codex-api`](../codex-api/README.md). It uses the existing HTTPS MCP and host OAuth for explicit scans. This directory remains the optional local runtime distribution with separately installed CLI and trusted hooks. Do not submit this hook-bearing runtime package as the public ZIP.
