# Install Patronus

This procedure installs a checksummed prebuilt CLI and immediately starts its
interactive onboarding. It does not clone the source repository. Onboarding
configures the scanner, proves the selected protection level with a visible
injection, and offers plugins for every detected Codex, Claude Code, or `dsh`
host.

## Standard installation

Run this in an interactive macOS or Linux terminal:

```console
curl -fsSL https://raw.githubusercontent.com/patronus-protect/patronus-security-cli/main/install.sh | sh
```

The installer writes only the executable to `~/.local/bin`, preserves an
existing installation until all download and health checks pass, and then runs
`patronus-security-scanner onboarding`. Add `~/.local/bin` to `PATH` if the
installer reports that it is missing.

## Instructions for an agent

An agent may execute the installation after the user authorizes writes to
`~/.local/bin` and the interactive onboarding. It must not invent answers, pipe
answers into onboarding, request credentials in chat, or execute a scanner from
the repository being inspected.

If the agent cannot attach the installer to an interactive terminal, install
first and open onboarding visibly on macOS:

```console
curl -fsSL https://raw.githubusercontent.com/patronus-protect/patronus-security-cli/main/install.sh | sh -s -- --no-onboarding
patronus-security-scanner onboarding --open
```

After the user finishes onboarding, the agent verifies configuration and each
selected integration:

```console
patronus-security-scanner onboarding --status --format json
patronus-security-scanner integration codex status --format json
patronus-security-scanner integration claude status --format json
patronus-security-scanner integration deepseek status --profile headless --format json
```

Only query hosts that were selected. A manifest alone is not proof of runtime
protection; the host must be restarted and its installed-host protection check
must pass before it is treated as ready.
