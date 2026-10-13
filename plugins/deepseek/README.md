<p align="center">
  <a href="../../README.md"><img src="../../docs/img/providers/deepseek.svg" width="96" alt="DeepSeek"></a>
</p>

<h1 align="center">Patronus Security for DeepSeek Harness</h1>

Patronus Runtime Protection integrates with the native Cordis lifecycle in DeepSeek Harness. Each Harness agent gets its own authenticated local scanner session; the integration never bundles or downloads a replacement CLI.

## Install

Install the supported DeepSeek Harness CLI first:

```sh
npm install --global @deepseek-ai/dsh@0.1.2-rc.1
```

Then select DeepSeek during Patronus onboarding. It detects `dsh`, downloads the matching Patronus package, installs it into the `headless` profile and enables protection automatically:

```sh
patronus-security-scanner onboarding
```

To add DeepSeek later:

```sh
patronus-security-scanner integration deepseek install
```

For installation by an agent, provide [`INSTALL.md`](INSTALL.md).

Restart the Harness after installation. Try:

> Check this repository with Patronus.

> Patronus status.

## What the native gates do

| Harness event | Patronus behavior |
| --- | --- |
| `agent/pre-step` | Scans new user-authored text before an agent step begins. |
| `llm/stream` | Enforces the same prompt gate immediately before a model stream as a second native boundary. |
| `tools/pre-execute` | Marks Patronus-owned tools before dispatch so their trusted receipts are not rescanned as external content. |
| `tools/post-execute` | Scans tool-result text and MCP `content[].text` before the next model turn. |
| `tools/result` | Detects a host projection that changed after the gate and adds degraded context to the next turn. |
| `agent/disposed` | Closes the agent's scanner process and private session handles. |

Multiple text blocks retain their order, and JSON-looking text remains raw. Images, paths, tool names, arguments, envelope keys, metadata and media bytes are outside scanner input.

## Runtime flow

1. The Harness exposes user input or a completed tool result through its native event bus.
2. Patronus selects only the external text covered by the runtime contract.
3. The installed CLI scans it under a session capability derived from the real Harness agent identity.
4. Clean text continues. Findings return a bounded receipt or an available redacted result without exposing the dangerous original.
5. Pending work remains tied to that agent session and can be checked without repeating the source tool.

Exact chat messages `patronus off`, `patronus on` and `patronus status` control protection for the current agent session.

## Fail-open behavior

Patronus is fail-open when scanning infrastructure is unavailable. Missing authentication, exhausted API usage, scanner startup errors, timeouts or an unavailable API do not block the underlying Harness tool. The original result continues with an explicit Patronus degraded message and must be treated as unverified. An unavailable scan is never reported as approved.

A completed finding is enforced: dangerous prompt or result text does not continue as an approved original. Fully covered PII/DLP-only results may use the separately retrieved masked view.

## Degraded or inactive messages

Unless a message says the content was scanned locally, it was not scanned and remains unverified. Scanner and integration failures name their public reason in parentheses. Commands below are `patronus-security-scanner` subcommands.

| Message or reason | Cause | Fix |
| --- | --- | --- |
| `Patronus protection is inactive for this content` without a reason, or a receipt saying `Patronus is unavailable or inactive` | No scan result came back and no cause was reported: the plugin is disabled or its scanner is missing or broken. | `integration deepseek status --format json`, then `integration deepseek enable` |
| `Patronus is not signed in to the API`, `Your Patronus login has expired`, `The Patronus API rejected the saved login` | API scanning needs a valid login. If the message says `scanned locally instead`, the content was still scanned. | `auth login` |
| `Patronus API usage limit reached` | The account's usage or rate limit is exhausted; the message gives the seconds until the API is available again. | `auth usage`; wait for the reset or raise the plan at https://control.patronus.studio/ |
| `api_timeout`, `api_unavailable`, `api_invalid_response`, `api_request_rejected` | The Patronus API did not answer, could not be reached or rejected the request. | Check connectivity and `auth status --check`, then retry |
| `broker_unavailable`, `runtime_start_failed`, `scanner_connection_lost`, `invalid_scanner_response`, `hook_input_invalid`, `hook_error` | The local integration (broker, scanner process or hook) failed. | `integration deepseek status --format json`, then `integration deepseek enable` |
| `runtime_version_mismatch` | The installed CLI and the plugin are different releases. | `maintenance update`, then `integration deepseek update`, and restart |
| `configuration_unavailable` | The scanner configuration is invalid or unreadable. | `config print --format json` and fix the reported file |
| `scan_timeout`, `payload_too_large`, `unsupported_content`, `unsupported_payload`, `invalid_chunking` | The content is too large, too slow to scan or in an unsupported shape. | Raise `scan_timeout_ms` or `max_payload_bytes` ([configuration](../../docs/configuration.md)) or treat the content as unverified |
| `local_scanner_error`, `scanner_crashed`, `incomplete_classification`, `invalid_classification`, `invalid_evidence_span` | The local scanner or a classifier failed on this content. | `assets prepare` for L2/L3 profiles; if it repeats, report it with `support-us` |

## Manage the integration

Open `patronus-security-scanner dashboard` to review activity and change policy. Restart the Harness after installation or an update.

```sh
patronus-security-scanner integration deepseek status
patronus-security-scanner integration deepseek update
patronus-security-scanner integration deepseek uninstall
```

Node.js 22.19 or newer, the pinned `dsh` release and the matching Patronus Security CLI release are required.

Licensed under Apache-2.0. The package includes `LICENSE` and `THIRD_PARTY_NOTICES.md`.
