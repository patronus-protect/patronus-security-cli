# Changelog

## Unreleased

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
  remains local with Ark 0.1.6.
- Upgrade the local scanner to Ark 0.1.6 and its ORT rc.13 dependency.
- Add a persistent local stdio runtime and native DeepSeek request/response gates, configurable
  500-ms response waits, and agent polling through pending receipts. Dangerous originals remain
  private; only approved originals or separately redacted dangerous responses can be retrieved.
- Bound runtime chunk preparation by the scan deadline while preserving static scan chunk records.
- Preserve cached model classifications when optional decision metadata is absent; expose bounded
  model-level metadata in runtime findings. Retain the known Ark 0.1.6 long-document detection
  regression and document separately validated L2/L3 tool flows.

## 0.1.0 - 2026-08-11

- Initial standalone scanner, deterministic artifacts, opt-in support bundles, and Codex/Claude plugin adapters.
- Updated the analysis engine to `patronus-ark 0.1.3`.
- Project every Ark evidence span as a separate deduplicated finding with its own confidence and
  exact byte and line range.
- Prefer positive native L1 category results over sibling no-match detector results.
- Add 10–40 KiB realistic finance, threat-intelligence, and benign operations fixtures with scan
  contracts for a prompt-injection case and a model-backed threat case that both remain clean in
  the complete default L1 profile.
