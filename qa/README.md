# QA routine

The recurring QA and UX loop measures hooks, SDKs, docs, the control dashboard and integrations, files findings as GitHub issues (label `qa`) and proposes small fixes as draft PRs. It runs locally as Claude Desktop scheduled tasks through the `/qa-run` skill (`.claude/skills/qa-*`).

| Script | What it measures | Side effects |
|---|---|---|
| `node qa/hooks.mjs [--quick] [--live]` | hook success, error, timeout and latency rates, detection recall and false positives on `hooks/corpus.json`, cold start, message length, scripted Claude/Codex host suites | Hooks run only in a temporary sandbox; the global host config is verified unchanged |
| `node qa/sdk.mjs` | published SDK versions, README quick starts from a fresh install | Temporary directories only |
| `node qa/integrations.mjs` | host CLI drift, manifest versions, runtime probe, integration status, OpenAPI drift, hosted MCP | Read-only |
| `node qa/lib/issues.mjs [--publish]` | Upserts today's findings as issues | Dry run unless `--publish` |

Reports are written to `~/.patronus-qa/runs/<date>/<area>.json`, and the metrics history goes to `~/.patronus-qa/history.jsonl`. Thresholds are in `qa/thresholds.json`.

## One-time setup

1. QA API key: create `~/.patronus-qa/env` with `PATRONUS_QA_API_KEY=...`, then run `chmod 600 ~/.patronus-qa/env`.
2. QA account for live hook runs: run `PATRONUS_DATA_DIR=~/.patronus-qa/data patronus-security-scanner auth login`, using the QA account.
3. Dashboard: sign in the QA account once in Claude's built-in browser. The routine never enters passwords.
4. `gh auth status` must have access to this repository.

## Hook lifecycle journaling

Hooks append `hook_started` and `hook_completed` protocol events when `PATRONUS_HOOK_TRACE=1` is set. The completed event records the decision, outcome, error code, duration and scan count. A start without a completion means the host killed the hook. Journaling is off by default, so normal hook latency is unchanged.
