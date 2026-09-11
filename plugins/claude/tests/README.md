# Claude native host proof

Tested on Claude Code **2.1.224**, binary SHA-256 `391df9d2ab04e4cf32199335720ac7715a582e91ecfd4d2198a16f57ea59b3`, with Node 22.22.3. The fixture uses a localhost scripted Anthropic protocol server, isolated Claude configuration, an environment allowlist, dummy credential, and local MCP process. It records request bodies but never authorization headers. Token/cost counters in Claude output are synthetic fixture usage, not paid calls.

From the repository root:

```sh
node --experimental-strip-types --test plugins/claude/tests/mapper.test.mjs
node --test plugins/claude/tests/claude-host.test.mjs
node --test plugins/claude/tests/claude-runtime.test.mjs
PATRONUS_CLAUDE_LIVE=1 node --test plugins/claude/tests/claude-live.test.mjs
```

`claude-live.test.mjs` is the acceptance/UX test. It removes API-key and base-URL
overrides, uses the signed-in Claude membership session and a real first-party
Claude model, loads the shipped plugin, and runs the normal Patronus scanner.
It covers an ordinary read, automatic PII redaction, a real mini Git repository,
URL and MCP audits, and an injection read. It emits only structured outcomes;
the raw Claude stream stays in its private temporary fixture directory.

The real-host commands need localhost socket permission. Runtime tests additionally require the rebuilt `plugins/claude/scripts/patronus.mjs` and installed local scanner. `PATRONUS_CLAUDE_BINARY` overrides the CLI path; `PATRONUS_PROOF_SCANNER` overrides the installed scanner path for runtime tests. The checked fixture defaults to the scanner location used for this proof.

Each host case writes `requests.json`, `transcript.jsonl`, `hooks.jsonl`, `hook-outputs.jsonl`, and bounded local fixture state under `/private/tmp/patronus-claude-native-proof`. Raw markers are synthetic. Assertions inspect every model request and the streamed tool transcript, plus execution markers and event sequences where relevant.

- Mapper tests validate exact external-text extraction, tool-name-independent replacement, ordered mixed-media text blocks, raw JSON-string preservation, and safe replacement shapes.
- Host tests run the installed CLI with deterministic hook decisions and the production mapper. They test the transport contract only; they do not test or make claims about Claude's model behavior or UX. They prove the exact `UserPromptSubmit.prompt` value is visible before the first model request; Bash/Read replacement; plain, JSON-looking, and mixed-media MCP text visibility; exact failure-result text visibility; exact placeholder transport and authoritative session identity; non-blocking inactive warnings; usable resumed sessions; and plugin discovery using the shipped manifest/config files with a fixture transport stub.
- Runtime tests run the installed CLI with the **built shared controller/broker and installed local scanner**. They prove pending Bash replacement; real scanner-unavailable warning and continuation; usable resumes after MCP errors; ordinary/placeholder request denial without PostToolUseFailure; and generic MCP text handling.
- Live tests are the only tests in this directory that assess real Claude behavior and end-to-end UX. They require an explicit opt-in because they contact Claude and the remote Patronus audit API.
- Negative controls establish the limits: MCP structured metadata survives in the transcript. The production timeout test runs the shipped bundle directly with a deterministic delayed local scanner peer and proves a timed-out result hook does not stop the CLI task.

Ordinary `PreToolUse` requests are outside the runtime text contract and are not scanned. Patronus' own placeholder tools are still intercepted before execution. Successful production `PostToolUse` replacement uses `updatedToolOutput` matching the hook-visible result shape. Plain strings are replaced as strings; Bash/Read structures retain safe native shapes; ordered text blocks are replaced without including adjacent media in scanner input. When protection is inactive, `additionalContext` warns the model while the original host result and chat remain usable. Claude PostToolUse `decision:"block"` does not implement replacement.

Do not infer complete host-history erasure, protection when a hook never starts, background/subagent protection, or arbitrary MCP envelope replacement from these results. Independent review is coordinated separately by the main implementation task.
