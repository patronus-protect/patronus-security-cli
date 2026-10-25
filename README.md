<p align="center">
  <img src="plugins/codex/assets/icon.png" width="112" alt="Patronus shield">
</p>

<h1 align="center">Patronus Security</h1>

<p align="center">
  Local-first runtime protection and security scans for AI agents.
</p>

Patronus Security combines the Patronus Security CLI (the `patronus-security-scanner` executable) with optional Runtime Protection integrations for Codex, Claude Code and DeepSeek Harness, and Guard Input steps for n8n, Make, Zapier, Dify and Activepieces. Patronus Ark powers detection. The integrations inspect external text before it reaches the model; completed findings keep dangerous content behind a verifiable receipt.

## Plugins

<table>
  <tr>
    <td align="center" width="33%">
      <a href="plugins/codex/README.md"><img src="docs/img/providers/codex-app.png" width="72" alt="Codex app"><br><strong>Codex</strong></a>
    </td>
    <td align="center" width="33%">
      <a href="plugins/claude/README.md"><img src="docs/img/providers/claude.svg" width="72" alt="Claude"><br><strong>Claude Code</strong></a>
    </td>
    <td align="center" width="33%">
      <a href="plugins/deepseek/README.md"><img src="docs/img/providers/deepseek.svg" width="72" alt="DeepSeek"><br><strong>DeepSeek Harness</strong></a>
    </td>
  </tr>
  <tr>
    <td>Native prompt, tool-result and MCP-result hooks.</td>
    <td>Native lifecycle, prompt and result hooks.</td>
    <td>Native Cordis request and response gates.</td>
  </tr>
</table>

Choose the hosts you use during onboarding. Each plugin page explains its hooks, protected flow and degraded behavior.

Patronus Security is an independent project and is not endorsed by OpenAI,
Anthropic, DeepSeek, n8n, Make, Zapier, Dify or Activepieces. Third-party names and logos identify compatibility only;
see [Third-party notices](THIRD_PARTY_NOTICES.md).

## Automation integrations

Put **Patronus → Guard Input** between user input or retrieved RAG context and the LLM
step of your workflow. It releases the exact text only after a complete, clean scan;
otherwise the step stops and the LLM never runs. No CLI on the automation host: the step
calls the Patronus API with your [API key](https://control.patronus.studio).

<table>
  <tr>
    <td align="center" width="20%">
      <a href="plugins/automations/n8n/README.md"><img src="docs/img/providers/n8n.svg" width="56" alt="n8n"><br><strong>n8n</strong></a>
    </td>
    <td align="center" width="20%">
      <a href="plugins/automations/make/README.md"><img src="docs/img/providers/make.svg" width="56" alt="Make"><br><strong>Make</strong></a>
    </td>
    <td align="center" width="20%">
      <a href="plugins/automations/zapier/README.md"><img src="docs/img/providers/zapier.svg" width="56" alt="Zapier"><br><strong>Zapier</strong></a>
    </td>
    <td align="center" width="20%">
      <a href="plugins/automations/dify/README.md"><img src="docs/img/providers/dify.svg" width="56" alt="Dify"><br><strong>Dify</strong></a>
    </td>
    <td align="center" width="20%">
      <a href="plugins/automations/activepieces/README.md"><img src="docs/img/providers/activepieces.svg" width="56" alt="Activepieces"><br><strong>Activepieces</strong></a>
    </td>
  </tr>
  <tr>
    <td>Community node <a href="https://www.npmjs.com/package/n8n-nodes-patronus"><code>n8n-nodes-patronus</code></a>: Settings → Community Nodes.</td>
    <td>Patronus app via invite link; Make app review pending.</td>
    <td>Patronus integration via invite link; Zapier listing pending.</td>
    <td>Plugin package from the <a href="https://github.com/patronus-protect/patronus-security-cli/releases/tag/automation-v0.1.1">automation release</a>.</td>
    <td>Piece <a href="https://www.npmjs.com/package/@patronus-protect/piece-patronus"><code>@patronus-protect/piece-patronus</code></a> or the release tarball.</td>
  </tr>
</table>

Chatbot and RAG examples for n8n, Make and Zapier, verified end to end on each platform,
are in [`plugins/automations/examples`](plugins/automations/examples/README.md). Setup,
guarantees and maintainer notes: [automation integrations](plugins/automations/README.md).

## Install

Install the latest release on macOS or Linux:

```sh
curl -fsSL https://github.com/patronus-protect/patronus-security-cli/releases/latest/download/install.sh | sh
```

The installer detects the platform, verifies the matching CLI artifact, installs
`patronus-security-scanner` to `~/.local/bin`, and opens onboarding. It does not
require an account for local protection.

To pin a specific release, replace the version in this URL:

```sh
curl -fsSL https://github.com/patronus-protect/patronus-security-cli/releases/download/v0.1.5/install.sh | sh
```

Release checksums are available on the [GitHub Releases](https://github.com/patronus-protect/patronus-security-cli/releases) page for manual verification.

**Installing with a coding agent?** Point it at the
[agent installation runbook](https://github.com/patronus-protect/patronus-security-cli/blob/main/INSTALL.md),
for example: *"Install Patronus by following
https://github.com/patronus-protect/patronus-security-cli/blob/main/INSTALL.md"*.
The runbook also covers checksum-first installation and what the agent may and
may not do.

## API clients

Applications can submit scans directly with the small, contract-tested
[Rust, TypeScript and Python API clients](sdk/README.md). Each client README
includes registry installation, a quick start and error behavior. Each client
directory also contains a dedicated `INSTALL.md` that a coding agent can follow
without receiving your API key.

The [automation integrations](#automation-integrations) use the same account API.

## Onboarding

Onboarding guides you through a short setup:

1. Sign in when you want cloud-backed features. Local protection works without an account.
2. Choose Local, Hybrid or API processing.
3. Patronus uses L3 analysis. For Local mode it measures a 256-token L3 check and recommends Hybrid when that takes more than 200 ms.
4. Run a visible injection check in the final processing mode.
5. Choose Full protection, Scanner + skills without automatic hooks, or CLI only. For either agent integration, select the detected hosts you use.

Run onboarding again at any time:

```sh
patronus-security-scanner onboarding
```

Run `patronus-security-scanner` without arguments in an interactive terminal to
open quick actions for scans, setup status, the dashboard and onboarding.
Arrow keys and Enter select an action; number keys select one directly. In
non-interactive use, the same command prints CLI help. Choosing onboarding keeps
the setup steps and their output in the terminal.

If you install another host later, either rerun onboarding or use one direct command:

```sh
patronus-security-scanner integration codex install
patronus-security-scanner integration claude install
patronus-security-scanner integration deepseek install
```

## Try it in a chat

Start a new agent chat after onboarding, then ask naturally:

> Check this repository with Patronus.

> Check this file with Patronus: `README.md`

> Check this URL with Patronus: `https://example.org`

> Patronus status.

Runtime protection is automatic. In a supported chat, `patronus on`, `patronus off`, and `patronus status` control or explain protection for that chat.

## Dashboard

Open the local dashboard to review activity, finish setup and adjust protection:

```sh
patronus-security-scanner dashboard
```

The dashboard runs on loopback and stores reports and settings on this device by default.

## Account

An account is optional for local checks, anonymous public URL scans, and explicit anonymous document uploads. Sign in for account usage, authenticated API processing, higher allowances, and MCP-server scans:

```sh
patronus-security-scanner auth login
patronus-security-scanner auth status
patronus-security-scanner auth logout
```

The browser provides a one-time code; do not paste API tokens into an agent chat.

## Reset or uninstall

Rerun `patronus-security-scanner onboarding` to reset setup choices without losing reports. To remove the CLI and all registered plugins:

```sh
patronus-security-scanner maintenance uninstall --all --yes
```

Saved settings, reports and credentials are preserved. Use `patronus-security-scanner auth logout` separately when you also want to disconnect the account.

## What Patronus covers

The [runtime text contract](docs/runtime-text-contract.md) defines the text each integration must scan and the host verification required to establish delivery and withholding. Installation status alone is not a live end-to-end check.

To check a live Codex or Claude session, ask the agent to run `patronus-security-scanner probe` through its normal shell tool. The command prints only a fixed harmless marker. After a complete scan, the result hook returns `status=probe_scanned`, the scan verdict, coverage and host context in place of the raw tool output. Seeing the raw marker means the result was not withheld. This checks that shell-result path in the current session; it does not certify every host tool or future session. Runtime receipts include the observed host, hook event and text surface when the hook supplies them. `delivery=hook_requested_unverified` means the hook requested replacement; only a host-level test or observed model request can prove delivery.

Patronus checks supported text for prompt injection, sensitive data and configured Ark classifications. Plugin protection covers user-prompt text, tool-result text and MCP text blocks. It does not scan tool requests, paths, metadata or media bytes.

MCP appears in three distinct places: the Patronus tools expose explicit scans, pending-result checks and redacted reads; runtime integrations protect text returned by foreign MCP servers; and an explicit audit of a public MCP server is a remote scan. Public URLs use the rate-limited anonymous API when no account credential is available. MCP-server audits remain authenticated. File, directory and repository scans extract UTF-8/UTF-16 text plus text from PDF and DOCX files on-device. In hybrid mode, every chunk from a file above 2048 tokens is analyzed through the API. Add `--anonymous-api` only when you explicitly want to upload one complete TXT, Markdown, HTML, PDF, or DOCX document.

Patronus is not a general SAST, dependency, CVE, malware or runtime-behaviour scanner. A clean result is useful evidence, not proof that arbitrary software is safe.

For exact behavior, see [configuration](docs/configuration.md), [privacy](docs/privacy.md), the [runtime text contract](docs/runtime-text-contract.md), and the [threat model](docs/threat-model.md).

## License

The Patronus Security CLI and its first-party integrations are the Apache-2.0-licensed community project. The CLI depends on the separately licensed first-party `patronus-ark` engine, which remains GPL-3.0-only and is explicitly approved by the repository's package-scoped license policy. Third-party components and model assets retain their own terms; see [licensing notes](docs/licensing.md), [`deny.toml`](deny.toml), and `THIRD_PARTY_NOTICES.md`.
