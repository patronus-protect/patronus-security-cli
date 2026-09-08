# Install Patronus Security

Patronus installs from a verified public GitHub release. You do not need Git, Cargo, a repository checkout, or a manually extracted plugin archive.

## Install and configure

Run in an interactive macOS or Linux terminal:

```sh
curl -fsSL https://raw.githubusercontent.com/patronus-protect/patronus-security-cli/main/install.sh | sh
```

The installer places the CLI in `~/.local/bin`, verifies that it starts, and launches onboarding. In onboarding, choose processing and analysis settings, run the visible safety check, then select the detected Codex, Claude Code or DeepSeek hosts you want to protect. Plugin downloads and installation are automatic.

Start a new agent chat when onboarding asks you to. Try:

> Check this repository with Patronus.

Then open the dashboard:

```sh
patronus-security-scanner dashboard
```

## Let an agent help

An agent may run the installer after the user authorizes installation into `~/.local/bin`. The user must make the interactive onboarding choices and complete browser authentication personally. The agent must never request a token in chat or execute a scanner binary supplied by the repository being inspected.

If the agent cannot attach onboarding to an interactive terminal, it may install first and open setup visibly:

```sh
curl -fsSL https://raw.githubusercontent.com/patronus-protect/patronus-security-cli/main/install.sh | sh -s -- --no-onboarding
patronus-security-scanner onboarding --open
```

## Account and reset

Local checks do not require an account. Use `patronus-security-scanner auth login` for cloud-backed features and `patronus-security-scanner auth logout` to disconnect.

Rerun `patronus-security-scanner onboarding` whenever you want to change setup or add a newly installed agent host. To remove the CLI and all registered plugins:

```sh
patronus-security-scanner maintenance uninstall --all --yes
```

Reports, settings and credentials remain on the device unless you remove them separately.
