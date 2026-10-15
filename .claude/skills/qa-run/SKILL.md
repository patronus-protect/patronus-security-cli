---
name: qa-run
description: Run the Patronus QA and UX routine (hooks, SDKs, docs, control dashboard, integrations), file findings as GitHub issues labelled qa and open up to three draft PRs with fixes. Use for the scheduled QA runs or when asked to "run QA".
argument-hint: "[--areas hooks,e2e,integrations,sdk,dx,dashboard | all] [--live]"
---

# Patronus QA run

You orchestrate one QA run. Measure first, then improve. Never merge anything.

## Areas

Parse `--areas` from the arguments (default `all` = hooks, e2e, integrations, sdk, dx, dashboard).

| Area | How |
|---|---|
| hooks | Follow `.claude/skills/qa-hooks/SKILL.md` |
| e2e | `node qa/e2e/run.mjs` (scripted, Claude and Codex, daily); with `--live` also `node qa/e2e/run.mjs --hosts claude --mode live` (weekly, paid turns). Then review its findings, see below |
| integrations | Follow `.claude/skills/qa-integrations/SKILL.md` |
| sdk | `node qa/sdk.mjs` (deterministic), then review its findings |
| dx | Follow `.claude/skills/qa-dx/SKILL.md` (docs, examples, SDK readability) |
| dashboard | Follow `.claude/skills/qa-dashboard/SKILL.md` (control.patronus.studio in Chrome) |

Run the areas in the order above. One failing area must not stop the others.

### e2e review

Read `~/.patronus-qa/runs/<date>/e2e.json`. `metrics.hosts.<host>.matrix` has one row per step (first receipt, protocol trail, final status, latency, leaks); the live run is under `metrics.live`.
- **Leaks** (critical): a canary, secret or PII value reached a model request. The row names the step whose output first carried it; check which tool result shape the hook did not scan.
- **False positives and recovery**: `false_positives` counts benign and mixed steps that were withheld first, how many the protocol recovered, the extra calls and the extra latency. An unrecovered one is high; a recovery that leaks is critical.
- **Consent**: `consent-deny` must keep every value masked; `consent-approve` must reveal exactly the requested type (emails) while IBANs stay masked.
- **Prompt gate**: `prompt_gate_phases` must read first:blocked, resend:sent, reuse:blocked, other-text:blocked (`ignore_once` is single-use and bound to the text). The gate session enables `analysis.user_prompt_pii`.
- **Live**: whether the real model followed the receipt protocol on its own (`protocol`, `consent.reveal_requested`), task success, turns and cost.
- If the baseline check fails, the scenario itself is broken; fix the fixture before trusting the protected numbers.

## Setup

1. Work from an up-to-date `main`: `git fetch origin && git switch main && git pull --ff-only`. If the tree is dirty, stop and report: another session is working here.
2. Build what the scripts use: `cargo build --release -q` (the QA always measures the release scanner; debug builds are ~25x slower) and `node plugins/native/scripts/build.mjs`.
3. Today's run directory is `~/.patronus-qa/runs/<YYYY-MM-DD>/`. All scripts write their `<area>.json` there.
4. Secrets come from `~/.patronus-qa/env` (`PATRONUS_QA_API_KEY`). Never print, log or paste the key anywhere, including issues and PRs.

## Findings

- Deterministic scripts produce findings in their report JSON. Agentic areas add findings by writing `~/.patronus-qa/runs/<date>/<area>.json` in the same shape (`schema: patronus.qa.report.v1`; findings use `area`, `severity` = critical|high|medium|low, a stable `fingerprint` of the form `qa:<area>:<slug>`, `title`, `evidence`, `suggestion`).
- A fingerprint must be stable across runs. Derive it from what is wrong, not from today's values.
- Before filing, re-check any finding that seems surprising (rerun the one command). Drop findings you cannot reproduce.
- Publish: `node qa/lib/issues.mjs --publish`. This creates one issue per new fingerprint and comments on open ones.

## Improvements (draft PRs)

At most **3 draft PRs per run**, each small and focused. Pick the highest-severity findings that can be fixed inside this repository with confidence:
- Hook behaviour or messages in `plugins/native/src/` and `plugins/deepseek/src/`, with a test in `plugins/native/tests/`. Rebuild with `node plugins/native/scripts/build.mjs` and commit the bundles.
- `docs/*.md`, SDK READMEs, `INSTALL.md` files, `examples/`.
- Version pins such as `.github/release-host-versions.env`, but only after the hook QA passed against the newer host.

For each PR:
1. Create a branch `qa/<date>-<slug>` from `main`.
2. Make the change and run the relevant tests (`cargo test`, `node plugins/native/scripts/test.mjs <file>`, SDK tests).
3. Commit, push, and run `gh pr create --draft --label qa`. Reference the issue with `Refs #<n>`, not `Fixes`.
4. Switch back to `main`.

Do not attempt detection-quality changes in the scanner (Ark) or anything on control.patronus.studio or docs.patronus.studio. Those are issues only, because their source is not in this repository.

## Summary

Finish by writing `~/.patronus-qa/runs/<date>/summary.md`. It contains:
- one line per area with the check pass rate,
- the key metrics with their delta to the previous run (`~/.patronus-qa/history.jsonl`),
- the issues created or commented on and the draft PRs opened.

Reply with that summary.
