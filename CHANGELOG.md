# Changelog

## Unreleased

- Threat detection is now opt-in: onboarding no longer enables it at L2/L3 and keeps an explicit choice.
- When the Patronus API usage or rate limit is exhausted, scan locally instead in hybrid and API mode, and tell users and agents why (Claude, Codex, DeepSeek, CLI reports). If local scanning is unavailable, report the usage limit instead of "protection is inactive".
- In hybrid mode, an expired, missing or rejected Patronus login no longer leaves large results unscanned: they are scanned locally instead. Scans that cannot complete report the fixed reasons `authentication_expired`, `authentication_missing` or `authentication_rejected` with `patronus-security-scanner auth login` as the fix, instead of "protection is inactive" (Claude, Codex, DeepSeek, CLI reports, remote audits).
- Injection redaction narrows by iterative bisection on this device only: only still-flagged halves are split again, each finding has its own budget, and a finding that cannot be narrowed keeps its coarse mask without discarding the others. Findings without evidence spans now mask their chunk instead of the whole field.
- User prompts with only prompt-injection or threat findings are sent with a warning instead of being blocked; the model is told to treat embedded instructions as data. DLP/PII prompts stay blocked and now offer `ignore_once`, which works with pasted quoting and punctuation and survives a mismatched retry.
- Claude returns Patronus tool results as ordinary MCP results and shows a readable reason for blocked prompts.
- Changing the working directory no longer disables Claude runtime protection.

## 0.1.1 - 2026-09-17

- Add an interactive CLI start menu and show onboarding as five visible terminal steps.
- Refresh the local dashboard layout, account controls and scan entry point.
- Keep installed agent hosts visible in setup status and prevent repeated sign-in from replacing an active token.
- Tighten scan option validation and add local Rust, TypeScript and Python file-checker examples.

### Breaking CLI changes

- Remove the unused `--color` option from local scans.
- Accept `--server` only on `scan mcp`; `scan url` rejects it.
- Accept `--anonymous-api` only on `scan file`, and reject scan options that the anonymous upload ignores.
- Reject `--no-repo-config` outside `scan repo`, `--include`/`--ignore` on `scan file`, and `onboarding --format` without `--status` or `--check`.

## 0.1.0 - 2026-09-14

- Add package validation and gated crates.io, npm, and PyPI publishing for the three API clients.
- Add shared Rust, TypeScript, and Python Scan API clients, persistent anonymous
  URL-scan identities, and explicit `scan file --anonymous-api` document uploads.
- Organize Rust modules by domain while retaining existing public module aliases.
- Start queued scan execution budgets when a worker claims the job and expose
  queue state in runtime receipts. Use Ark's calibrated model decisions while
  preserving same-level DLP findings; retire plugin confidence overrides.
- Add rescanned static-file redaction, withholding results when findings are
  truncated, and preserve pending MCP protection through host content finalizers.
- Pin installers to a versioned release and stop installation instructions on
  checksum mismatch. Bound TypeScript API response bodies during streaming.
- Add an automated Cargo license policy that keeps Patronus Security under
  Apache-2.0 while explicitly approving the first-party GPL-3.0-only
  `patronus-ark` dependency.
- Gate releases on twelve installed-host E2E flows for Codex and DeepSeek, with
  artifact hashes, model-visible evidence, upgrade and scanner-recovery checks.
  Keep the suite opt-in outside release publishing.
- Fix Codex updates from local marketplaces: reinstall the local package and
  refresh hook trust without invoking the Git-only marketplace upgrade command.
- Add Codex and Claude native hook adapters with a shared local session broker, session-bound
  pending/status/redacted retrieval, and static scans that return bounded metadata. Completed findings
  are enforced while infrastructure failures fall open with explicit degraded context; scanner execution
  remains local with Ark 0.1.7.
- Upgrade the local scanner to Ark 0.1.7 and its ORT rc.13 dependency.
- Add a persistent local stdio runtime and native DeepSeek request/response gates, configurable
  500-ms response waits, and agent polling through pending receipts. Dangerous originals remain
  private; only approved originals or separately redacted dangerous responses can be retrieved.
- Bound runtime chunk preparation by the scan deadline while preserving static scan chunk records.
- Preserve cached model classifications when optional decision metadata is absent; expose bounded
  model-level metadata in runtime findings. Retain the known Ark 0.1.7 long-document detection
  regression and document separately validated L2/L3 tool flows.

- Initial standalone scanner, deterministic artifacts, opt-in support bundles, and Codex/Claude plugin adapters.
- Updated the analysis engine to `patronus-ark 0.1.3`.
- Project every Ark evidence span as a separate deduplicated finding with its own confidence and
  exact byte and line range.
- Prefer positive native L1 category results over sibling no-match detector results.
- Add 10–40 KiB realistic finance, threat-intelligence, and benign operations fixtures with scan
  contracts for a prompt-injection case and a model-backed threat case that both remain clean in
  the complete default L1 profile.
