<p align="center">
  <img src="plugins/codex/assets/icon.png" width="112" alt="Patronus shield">
</p>

<h1 align="center">Patronus Security</h1>

<p align="center">
  Local-first runtime protection and security scans for AI agents.
</p>

Patronus Security combines the Patronus Security CLI (the `patronus-security-scanner` executable) with optional Runtime Protection integrations for Codex, Claude Code and DeepSeek Harness. Patronus Ark powers detection. The integrations inspect external text before it reaches the model; completed findings keep dangerous content behind a verifiable receipt.

## Plugins

<table>
  <tr>
    <td align="center" width="33%">
      <a href="plugins/codex/README.md"><img src="plugins/codex/assets/icon.png" width="72" alt="Patronus for Codex"><br><strong>Codex</strong></a>
    </td>
    <td align="center" width="33%">
      <a href="plugins/claude/README.md"><img src="plugins/claude/assets/icon.png" width="72" alt="Patronus for Claude Code"><br><strong>Claude Code</strong></a>
    </td>
    <td align="center" width="33%">
      <a href="plugins/deepseek/README.md"><img src="plugins/deepseek/assets/icon.png" width="72" alt="Patronus for DeepSeek Harness"><br><strong>DeepSeek Harness</strong></a>
    </td>
  </tr>
  <tr>
    <td>Native prompt, tool-result and MCP-result hooks.</td>
    <td>Native lifecycle, prompt and result hooks.</td>
    <td>Native Cordis request and response gates.</td>
  </tr>
</table>

Choose the hosts you use during onboarding. Each plugin page explains its hooks, protected flow and degraded behavior.

## Install

Download the installer and its checksum from the fixed `v0.1.0` release, verify it, then run it:

```sh
version=v0.1.0
base="https://github.com/patronus-protect/patronus-security-cli/releases/download/$version"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' 0 HUP INT TERM
curl -fsSL "$base/install.sh" -o "$work_dir/install.sh"
curl -fsSL "$base/install.sh.sha256" -o "$work_dir/install.sh.sha256"
expected=$(awk 'NR == 1 { print $1 }' "$work_dir/install.sh.sha256")
if command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$work_dir/install.sh" | awk '{ print $1 }')
elif command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$work_dir/install.sh" | awk '{ print $1 }')
else
  echo "A SHA-256 tool (shasum or sha256sum) is required" >&2
  exit 1
fi
[ "$actual" = "$expected" ] || { echo "Installer checksum mismatch" >&2; exit 1; }
PATRONUS_VERSION="$version" sh "$work_dir/install.sh"
```

The installer downloads only the matching `v0.1.0` CLI artifact, verifies it against the checksum published with that release, installs `patronus-security-scanner`, and immediately opens onboarding. The checksum establishes integrity within the GitHub release channel; it is not an independent signature.

For a shorter convenience install that trusts the versioned GitHub release URL for the installer itself:

```sh
curl -fsSL https://github.com/patronus-protect/patronus-security-cli/releases/download/v0.1.0/install.sh | PATRONUS_VERSION=v0.1.0 sh
```

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

Patronus checks supported text for prompt injection, sensitive data and configured Ark classifications. Plugin protection covers user-prompt text, tool-result text and MCP text blocks. It does not scan tool requests, paths, metadata or media bytes.

MCP appears in three distinct places: the Patronus tools expose explicit scans, pending-result checks and redacted reads; runtime integrations protect text returned by foreign MCP servers; and an explicit audit of a public MCP server is a remote scan. Public URLs use the rate-limited anonymous API when no account credential is available. MCP-server audits remain authenticated. With the default local provider, `scan file report.pdf` stays local; add `--anonymous-api` only when you explicitly want to upload that TXT, Markdown, HTML, PDF, or DOCX document.

Patronus is not a general SAST, dependency, CVE, malware or runtime-behaviour scanner. A clean result is useful evidence, not proof that arbitrary software is safe.

For exact behavior, see [configuration](docs/configuration.md), [privacy](docs/privacy.md), the [runtime text contract](docs/runtime-text-contract.md), and the [threat model](docs/threat-model.md).

## License

The Patronus Security CLI and its first-party integrations are the Apache-2.0-licensed community project. The CLI depends on the separately licensed first-party `patronus-ark` engine, which remains GPL-3.0-only and is explicitly approved by the repository's package-scoped license policy. Third-party components and model assets retain their own terms; see [licensing notes](docs/licensing.md), [`deny.toml`](deny.toml), and `THIRD_PARTY_NOTICES.md`.
