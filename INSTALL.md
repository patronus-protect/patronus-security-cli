# Install Patronus Security

Patronus installs from the fixed public GitHub release `v0.1.0`. You do not need Git, Cargo, a repository checkout, or a manually extracted plugin archive.

## Install and configure

Download and verify the installer before running it in an interactive macOS or Linux terminal:

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

The installer fetches only the matching `v0.1.0` artifact, verifies it against the checksum published with that release, places the CLI in `~/.local/bin`, verifies that it starts, and launches onboarding. The checksum establishes integrity within the GitHub release channel; it is not an independent signature. Onboarding always configures L3. Local mode first measures a 256-token L3 check and recommends Hybrid above 200 ms, then runs the visible safety check in the final mode. Finally choose Full protection, Scanner + skills without automatic hooks, or CLI only; plugin downloads and installation for selected hosts are automatic.

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
curl -fsSL https://github.com/patronus-protect/patronus-security-cli/releases/download/v0.1.0/install.sh | PATRONUS_VERSION=v0.1.0 sh -s -- --no-onboarding
patronus-security-scanner onboarding --open
```

## Account and reset

Local checks and rate-limited anonymous URL scans do not require an account. `scan file PATH` is local by default; `scan file PATH --anonymous-api` explicitly uploads a supported document. Use `patronus-security-scanner auth login` for higher allowances and authenticated cloud features, and `patronus-security-scanner auth logout` to disconnect.

Rerun `patronus-security-scanner onboarding` whenever you want to change setup or add a newly installed agent host. To remove the CLI and all registered plugins:

```sh
patronus-security-scanner maintenance uninstall --all --yes
```

Reports, settings and credentials remain on the device unless you remove them separately.
