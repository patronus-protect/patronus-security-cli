<h1 align="center">Patronus Security for GitHub Copilot CLI</h1>

Patronus Runtime Protection adds security hooks to GitHub Copilot CLI (`copilot`). It checks outside text before the agent acts on it. The scanner, policy and session state stay in the separately installed Patronus Security CLI.

## Protection level: full (tool and MCP results)

Copilot hands every tool result to one hook as text (`textResultForLlm`), and the hook can replace it before the model sees it. The table was verified against the real `@github/copilot` 1.0.103 binary, running offline with a scripted model ([hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)):

| What reaches the agent | Copilot hook | Patronus behavior |
| --- | --- | --- |
| Your prompt | `userPromptTransformed` | Scanned. If it contains sensitive data, the model gets a Patronus notice instead (`modifiedTransformedPrompt`) and tells you how to resend once with `ignore_once`. An injection in your own prompt is sent with a warning appended. |
| Shell command (before it runs) | `preToolUse` (`bash`, `powershell`) | Checked. A risky command (exfiltration, `curl … \| sh`, but also `npm install`, `cat .env`) gets `permissionDecision: "ask"`. In prompt mode (`copilot -p`) and autopilot nobody can answer, so Copilot denies it. Patronus never blocks a command on its own. |
| Result of any built-in tool: `view`, `bash`, `grep`, `glob`, and per the hook contract also `web_fetch` and `task` (not exercised offline) | `postToolUse` | Scanned. A finding replaces the result (`modifiedResult`) with a receipt or the masked text. |
| MCP tool result (`<server>-<tool>`) | `postToolUse` | Scanned under the MCP policy and replaced the same way. |
| Error text of a failed tool | `postToolUseFailure` | Scanned, **not withheld**: Copilot cannot replace error text. Patronus adds a warning (`additionalContext`). |
| Custom instructions (`AGENTS.md`, `.github/copilot-instructions.md`), skills, attached images and files (`--attachment`), MCP resources | none | **Not scanned.** Copilot loads these without a hook. |

PII disclosure (`patronus_reveal_pii`) asks you through Copilot's permission prompt (`preToolUse` `ask`). Copilot denies it in prompt mode, autopilot and the cloud agent, and the agent continues with the masked result.

A hook that times out fails open in Copilot. Patronus answers within the timeout by returning a `pending` receipt for slow scans. The time limits are 330 s for `postToolUse` and 90 s for prompts.

### Copilot coding agent (cloud)

The cloud coding agent loads only `.github/hooks/*.json` from the repository. It does not load user hooks, plugins or MCP configuration, and its sandbox has no Patronus scanner. This integration therefore covers the Copilot CLI only.

### Claude Code hooks inside Copilot

Copilot CLI also runs hooks declared in a project's `.claude/settings.json` and `.claude/settings.local.json`, with Claude event names but Copilot's own payload. The Patronus Claude Code plugin recognizes that payload and stays out of the way. Copilot chats are protected by this integration.

## Install

```sh
patronus-security-scanner integration copilot install
```

The CLI downloads and verifies the matching release asset and copies the hook runtime to `~/.patronus-security-scanner/integrations/copilot`. It then writes its own hook file, `~/.copilot/hooks/patronus-security.json`, and adds the `patronus` entry to `~/.copilot/mcp-config.json` (or the same paths under `$COPILOT_HOME`). Other hook files and MCP servers stay as they are. Start a new `copilot` session afterwards. For installation by an agent, provide [`INSTALL.md`](INSTALL.md).

The directory also works as a Copilot plugin (`plugin.json`, `hooks/hooks.json`, `.mcp.json`), for example with `copilot --plugin-dir plugins/copilot` or `copilot plugin install patronus-protect/patronus-security-cli:plugins/copilot`. Install it only one way; otherwise every hook runs twice.

## Hooks

| Copilot hook | Patronus behavior |
| --- | --- |
| `userPromptTransformed` | Scans the prompt; handles `patronus on`, `patronus off` and `patronus status`. |
| `preToolUse` | Checks shell command lines before they run (ask) and asks before a PII disclosure. |
| `postToolUse` | Scans every tool and MCP result; answers Patronus' own MCP tools for this session. |
| `postToolUseFailure` | Scans a failed tool's error text (warning only). |
| `sessionEnd` | Releases the session's runtime state. |

Skills (`skills/`): `runtime` explains receipts, withheld prompts and held commands; `scan` runs explicit audits; `patronus-setup` guides installation.

The Patronus MCP server (`patronus_check_result`, `patronus_read_redacted`, `patronus_reveal_pii`, `patronus_scan`) answers with a placeholder. The `postToolUse` hook replaces it with the result for the current session.

## Fail-open behavior

Patronus is fail-open when its scanning infrastructure is unavailable. The prompt or tool result continues with a degraded note. Completed findings are enforced on the surfaces listed above. An unavailable scan is never reported as approved.

## Degraded or inactive messages

Unless a message says the content was scanned locally, it was not scanned and remains unverified. Commands below are `patronus-security-scanner` subcommands.

| Message or reason | Cause | Fix |
| --- | --- | --- |
| `Patronus protection is inactive for this content` with `Check:` and `Repair:` commands | No scan result came back and no cause was reported: hooks disabled, scanner missing or broken. | `integration copilot status --format json`, then `integration copilot enable` |
| `Patronus is not signed in to the API`, `Your Patronus login has expired`, `The Patronus API rejected the saved login` | API scanning needs a valid login. If the message says `scanned locally instead`, the content was still scanned. | `auth login` |
| `Patronus API usage limit reached` | The account's usage or rate limit is exhausted. | `auth usage`; wait for the reset or raise the plan at https://control.patronus.studio/ |
| `api_timeout`, `api_unavailable`, `api_invalid_response`, `api_request_rejected` | The Patronus API did not answer, could not be reached or rejected the request. | Check connectivity and `auth status --check`, then retry |
| `broker_unavailable`, `runtime_start_failed`, `scanner_connection_lost`, `invalid_scanner_response`, `hook_input_invalid`, `hook_error` | The local integration (broker, scanner process or hook) failed. | `integration copilot status --format json`, then `integration copilot enable` |
| `runtime_version_mismatch` | The installed CLI and the hook runtime are different releases. | `maintenance update`, then `integration copilot update` |
| `configuration_unavailable` | The scanner configuration is invalid or unreadable. | `config print --format json` and fix the reported file |
| `scan_timeout`, `payload_too_large`, `unsupported_content`, `unsupported_payload`, `invalid_chunking` | The content is too large, too slow to scan or in an unsupported shape. | Raise `scan_timeout_ms` or `max_payload_bytes` ([configuration](https://github.com/patronus-protect/patronus-security-cli/blob/main/docs/configuration.md)) or treat the content as unverified |
| `Patronus answers this tool in its result hook` | A Patronus MCP tool ran but the `postToolUse` hook did not replace its placeholder. | `integration copilot status --format json`, then start a new session |
| `Copilot cannot withhold error text` | Expected: a failed tool's error text was flagged, but Copilot delivers it unchanged. | Review the error yourself |
| `Denied by preToolUse hook (unable to ask user for confirmation)` | Expected in `copilot -p` and autopilot: Patronus asked about a risky command or a PII disclosure, and nobody could answer. | Run the command yourself, or use an interactive session |

## Manage the integration

```sh
patronus-security-scanner integration copilot status
patronus-security-scanner integration copilot disable
patronus-security-scanner integration copilot update
patronus-security-scanner integration copilot uninstall
```

`disable` keeps the hook file but sets `disableAllHooks: true` in it, which switches off only the Patronus hooks.

Requires GitHub Copilot CLI with hooks (1.0.103 was used for the contract), Node.js 22.19 or newer, and the matching Patronus Security CLI release.

Licensed under Apache-2.0. The release archive includes `LICENSE` and `THIRD_PARTY_NOTICES.md`.
