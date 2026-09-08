<p align="center">
  <img src="plugins/codex/assets/icon.png" width="112" alt="Patronus shield">
</p>

<h1 align="center">Patronus Security</h1>

<p align="center">
  Local-first security checks for AI agent chats, repositories, files and tools.
</p>

Patronus installs a small CLI and optional plugins for Codex, Claude Code and DeepSeek Harness. The plugins inspect external text before it reaches the model and keep dangerous content behind a verifiable receipt.

> One installer. One guided setup. No repository checkout and no archive paths.

## Install

Run this in a macOS or Linux terminal:

```sh
curl -fsSL https://raw.githubusercontent.com/patronus-protect/patronus-security-cli/main/install.sh | sh
```

The installer verifies the release, installs `patronus-security-scanner`, and immediately opens onboarding.

## Onboarding

Onboarding guides you through five short choices:

1. Sign in when you want cloud-backed features. Local protection works without an account.
2. Choose Local, Hybrid or API processing.
3. Choose the analysis level. L1 needs no model download.
4. Run a visible injection check.
5. Select any detected agent hosts. Patronus downloads and installs their plugins automatically.

Run onboarding again at any time:

```sh
patronus-security-scanner onboarding
```

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

An account is optional for local checks. Sign in for API processing, account usage, and public URL or MCP-server scans:

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

Patronus checks supported text for prompt injection, sensitive data and configured Ark classifications. Plugin protection covers user-prompt text, tool-result text and MCP text blocks. It does not scan tool requests, paths, metadata or media bytes.

Patronus is not a general SAST, dependency, CVE, malware or runtime-behaviour scanner. A clean result is useful evidence, not proof that arbitrary software is safe.

For exact behavior, see [configuration](docs/configuration.md), [privacy](docs/privacy.md), the [runtime text contract](docs/runtime-text-contract.md), and the [threat model](docs/threat-model.md).

## License

Patronus Security Scanner and its first-party plugins are licensed under [Apache License 2.0](LICENSE). Third-party components and model assets retain their own terms; see [licensing notes](docs/licensing.md) and `THIRD_PARTY_NOTICES.md`.
