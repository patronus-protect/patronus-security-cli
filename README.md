# Patronus Security Scanner

Patronus Security Scanner is a local-first command-line scanner for Git repositories, directories, and individual files. It uses Patronus Ark to classify supported text and source files, records complete coverage separately from findings, and can protect text entering supported AI-agent hosts through optional plugins.

Patronus is a content gate, not a general SAST, dependency, CVE, malware, or runtime-behaviour scanner. Ark classifications are probabilistic; a clean result does not prove that content is safe.

## Requirements

- A prebuilt CLI archive from this repository's GitHub Releases, or Rust/Cargo for a source build.
- Node.js 22.19 or newer for the Codex, Claude Code, and DeepSeek plugins.
- Local L1 scanning needs no downloaded model assets. L2/L3 requires assets prepared explicitly with `patronus-security-scanner assets prepare`.

Plugin bundles do not contain, download, or silently install the scanner executable. Install the trusted CLI separately and keep it on an absolute `PATH` entry. Never use a scanner binary supplied by the repository being inspected.

## Install and set up

The standalone installer needs no repository checkout. It verifies the installer backend and target-specific CLI archive before replacing `~/.local/bin/patronus-security-scanner`, then starts onboarding. The onboarding flow configures processing, runs a visible injection check, and offers to install plugins for detected Codex, Claude Code, and `dsh` hosts.

```console
curl -fsSL https://raw.githubusercontent.com/patronus-protect/patronus-security-cli/main/install.sh | sh
```

Use `--no-onboarding` only when installation runs without an interactive terminal. See [INSTALL.md](INSTALL.md) for agent-oriented and private-repository instructions. Rust and Cargo are not needed for a prebuilt release.

To build a checkout instead:

```console
cargo install --locked --path . --bin patronus-security-scanner
```

For a source build, confirm the installation and create an explicit configuration:

```console
patronus-security-scanner --version
patronus-security-scanner config init --provider local
patronus-security-scanner config print --format json
```

## First scan

```console
patronus-security-scanner scan repo .
patronus-security-scanner scan directory ./src --max-level l1
patronus-security-scanner scan file ./README.md --progress off
```

Reports default to `~/.patronus-security-scanner/output/<run-id>/`. Machine-readable results go to stdout with `--format json`; progress and diagnostics go to stderr. A result is `CLEAN` only when requested coverage completed with no findings. See [output format](docs/output-format.md).

## Agent plugins

Release archives for Codex and Claude Code contain their marketplace manifests and complete plugin directories. The DeepSeek integration is distributed as a `.tgz`. Extract the selected archive and install it with the CLI:

```console
patronus-security-scanner integration codex install --source /path/to/extracted-codex-archive
patronus-security-scanner integration claude install --source /path/to/extracted-claude-archive
patronus-security-scanner integration deepseek install --profile headless --source /path/to/patronus-deepseek-security.tgz
```

Restart the host, then verify the installed integration:

```console
patronus-security-scanner integration codex status --format json
```

Replace `codex` with `claude` or `deepseek` as needed. The same command group provides `enable`, `disable`, `update`, and `uninstall`. Host-specific instructions are included in each release archive and in this repository:

- [Codex plugin](plugins/codex/README.md)
- [Claude Code plugin](plugins/claude/README.md)
- [DeepSeek plugin](plugins/deepseek/README.md)

An installed manifest or visible MCP tool alone does not prove enforcement. Before relying on a plugin, verify mock visibility, enforcement, and installed-host behaviour. The exact text boundary is defined by the [runtime text contract](docs/runtime-text-contract.md).

## Configuration and data handling

`provider.mode` is explicit:

- `local` processes scans on the device.
- `api` sends scan text to the configured Patronus API.
- `hybrid` keeps files and user prompts local; runtime tool/MCP results above the configured local threshold use the API.

There is no silent provider fallback. Local model downloads are disabled unless the user explicitly prepares assets or enables downloads. Reports stay on the device by default; source content and raw evidence are omitted from normal report artifacts. See [configuration](docs/configuration.md), [privacy](docs/privacy.md), and the [threat model](docs/threat-model.md).

## License

Patronus Security Scanner and its first-party plugin code are provided under the Apache License 2.0. See [LICENSE](LICENSE) and [licensing notes](docs/licensing.md). Third-party components and model assets remain subject to their own notices and terms.
