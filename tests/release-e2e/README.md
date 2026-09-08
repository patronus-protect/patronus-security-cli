# Release E2E: Codex and DeepSeek

Run this suite before every release, not on every edit or pull request. It starts
real host CLI processes, installs the supplied plugin bytes into private profiles,
and uses the supplied scanner executable. Only the model is scripted; scanner
verdicts, native hooks, tool dispatch, receipt retrieval and lifecycle commands
are real. No live model credentials are required.

The suite does **not** compile or silently replace the plugin under test. Point it
at an existing installed package to diagnose that installation, or at extracted
release artifacts to gate a release. It never changes the user's host profiles.

## Run

```sh
export PATRONUS_SCANNER_BIN=/absolute/path/to/patronus-security-scanner
export PATRONUS_CODEX_BIN=/absolute/path/to/codex
export PATRONUS_CODEX_PLUGIN_ROOT=/absolute/path/to/installed/codex/plugin
export DSH_SOURCE_ROOT=/absolute/path/to/deepseek-harness
export PATRONUS_DEEPSEEK_PLUGIN_ROOT=/absolute/path/to/installed/@patronus/deepseek-security
node tests/release-e2e/run.mjs --installed --out /tmp/patronus-release-report
```

`--installed` additionally checks the active host integration status before the
isolated flows. It is read-only and does not repair stale trust or enable plugins.
For packaged candidates, omit `--installed`.

For a release tarball, set `PATRONUS_DEEPSEEK_TARBALL=/absolute/path/release.tgz`
instead of `PATRONUS_DEEPSEEK_PLUGIN_ROOT`. Codex accepts the `plugins/codex`
directory from its extracted release archive. Use absolute paths.

Use the actual deployed Codex CLI, including the app-bundled executable when
checking desktop behavior. Its exact version is recorded; optionally enforce it
with `PATRONUS_CODEX_EXPECTED_VERSION`. The release workflow requires the repository
variable `PATRONUS_CODEX_RELEASE_VERSION` and refuses to fall back to an older CLI.
Desktop 0.153.4 was verified locally, including the stale-parent regression. DeepSeek uses the dependency-installed CLI checkout at
`76fda729799fe9b3848dbe2c211d4b231032b81e`, matching the plugin's peer dependencies.
The DeepSeek adapter starts `apps/cli/src/bin.ts` with its installed tsx loader;
it is the real headless profile runner, not a manually assembled agent loop.
The host tools resolver supports this source installation. Patronus is always
loaded from the package installed by `dsh plugin add`, never aliased to source.
Node 22.19+ and pnpm 11 are needed. Initial package installation can access the
package registry; scanner processing stays local with L1 and model downloads off.

For one failure, use `--host codex --flow read-redacted` (or `deepseek`). A focused
run is explicitly marked `releaseGate: false`; it is not a full release verdict.

## Fourteen small flows

Each of the following runs once per host:

| Flow | Action | Required observation |
| --- | --- | --- |
| `safe-read` | Read a tiny manifest. | Version/document marker reaches the model; source executes once. |
| `auto-pii` | Read the manifest with a synthetic email. | Only redacted email reaches the model; useful content remains; no manual redaction call. |
| `pending` | Read with zero response wait, then poll. | Actual pending receipt followed by approved content; no repeated source execution. |
| `read-redacted` | Read release notes containing an actual prompt-injection instruction, then request redaction. | The complete returned text exactly matches the golden file: only the injection span becomes `[REDACTED]`. Surrounding text, Unicode, numbers and newlines remain unchanged. |
| `remote-fail-open` | Request a URL audit in Local mode without API authentication, then use the requested source tool. | The packaged CLI reports the unavailable audit, the hook adds degraded context, and the agent still executes the source tool exactly once. |
| `upgrade` | Install a different previous package/definition, then invoke the public scanner update command. | Current package is restored, changed Codex hook trust is renewed, retrieval works and settings survive. |
| `outage-recovery` | Make scanner unavailable, then restore it. | The real CLI receives a model-visible inactive warning, keeps the original unscanned result usable, and succeeds normally after recovery. |

The injection flow uses [the original document](fixtures/injection-document.txt)
and an independent [expected redacted document](fixtures/injection-document.redacted.txt).
It must observe `dangerous`, explicitly invoke `patronus_read_redacted`, and receive
`redacted` with the exact expected text. The instruction must never reach model
input, and the source must execute exactly once. Detection and redaction are
performed by the real scanner; only the model's tool choices are scripted.

The upgrade fixture is a synthetic previous version of the candidate, not a
compatibility claim about every historical release. The Codex flows use Code Mode
and its nested native tools, including both Patronus retrieval tools.

## Evidence and release gate

`report.md` gives a short human-readable verdict. `report.json` records each PASS/FAIL, elapsed time, scanner version/hash, plugin
file hashes and host identity. Model inputs and host outputs are copied beside
the report. A missing host, setup failure, timeout, absent evidence or skipped
flow is a failure, never a green result. Tool return codes and `ready=true` alone
cannot pass a flow: the model-visible output and source execution count must match.

`.github/workflows/release.yml` runs this against the Linux CLI and plugin packages
produced by the release build. Publishing depends on the E2E job. The report is
uploaded even on failure. This verifies that release candidate on the pinned
hosts; it does not certify already running desktop sessions, other host versions,
L2/L3 model latency, API-provider processing or every operating system.

## Already running parent tasks

After updating hook definitions and saving new trust, an already loaded task can
still hold old trust and pass it to subagents. `integration codex status` from a
new CLI process cannot certify that task. Reload the parent task or restart the
host, then retrieve the existing receipt without repeating the source command.

`node tests/release-e2e/codex-subagent.mjs` reproduces this state on the supplied
CLI: start with stale trust, repair it while the parent is running, observe the
child's blocked retrieval, then resume the same parent in a fresh process and
retrieve the original scan. The source execution count must remain one. This
additional regression runs before publishing alongside the twelve content flows.
