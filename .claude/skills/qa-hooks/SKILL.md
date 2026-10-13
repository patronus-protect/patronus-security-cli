---
name: qa-hooks
description: Measure and improve the Patronus runtime hooks (Claude, Codex) — success rate, latency, detection utility and message quality — with hooks enabled only inside an isolated QA sandbox.
argument-hint: "[--live] [--quick]"
---

# Hook QA

The hooks must **never** be enabled in the global Claude or Codex configuration on this machine, because other local routines run here without hooks. `qa/hooks.mjs` handles the lifecycle:

1. **Preflight**: records `integration <host> status` and hashes of the global host config files. A globally active Patronus plugin becomes a finding.
2. **Enable in a sandbox only**. It uses three layers:
   - direct calls into the built hook bundles,
   - `claude --plugin-dir` with its own `CLAUDE_CONFIG_DIR`,
   - a temporary `CODEX_HOME` with a scripted model.

   Hook lifecycle journaling is switched on with `PATRONUS_HOOK_TRACE=1`.
3. **QA**:
   - replay of `qa/hooks/corpus.json` (detection recall, false positives, cold start, latency, message length),
   - the scripted Claude host suites,
   - the Codex release E2E flows,
   - with `--live`, a real Claude session against the QA account.
4. **Teardown**: closes every broker session and deletes the sandbox, also on SIGINT or SIGTERM.
5. **Postflight**: the global config hashes and the integration state must be unchanged.

## Steps

1. Run `node qa/hooks.mjs` (add `--live` on the weekly run). It takes about 20 minutes, and `--quick` runs the replay only. Never run `integration <host> enable|install` yourself.
2. Read `~/.patronus-qa/runs/<date>/hooks.json`. Check that every check is ok, especially `global host config unchanged`. If that check failed, stop and report it as critical. Do not restore files yourself.
3. Investigate the findings:
   - **Error or timeout rates**: look at `metrics.hooks[*].errors` and trace the error code in `plugins/native/src/hooks.ts`, `broker.ts`, `daemon.ts`.
   - **Detection misses**: look at `metrics.replay` rows with `expect=flag` and `verdict=pass`. Scanner quality lives in Ark, outside this repository, so file an issue that names the corpus case IDs.
   - **False positives**: rows with `expect=pass` and `verdict=flag`.
   - **Prompt policy**: `UserPromptSubmit` misses may be policy, not detection; compare with `plugins/deepseek/src/prompt-policy.ts`.
   - **Cold start / latency**: compare against `qa/thresholds.json` and the previous run in `~/.patronus-qa/history.jsonl`.
4. **Message UX**: read the hook messages a person or agent sees (`systemMessage`, `additionalContext`, warnings in `plugins/deepseek/src/notice.ts`, `failureMessage` in `hooks.ts`). Each message should say what happened, whether the content is safe to use, and the one next command. Record unclear or overlong messages as `ux` findings.
5. Grow the corpus when you find a realistic gap, such as a new injection style or a benign case that was flagged. Add cases to `qa/hooks/corpus.json` as part of a draft PR, using synthetic data only.

## Fixes worth a draft PR

- Error handling or fail-open paths that produce `hook_error`, `broker_unavailable` or timeouts.
- Hook messages that are unclear or too long.
- Starting the broker earlier, for example at SessionStart, if the cold start exceeds the threshold.
- Each fix needs a test in `plugins/native/tests/`, rebuilt bundles, and a green `node qa/hooks.mjs --quick` run.
