# Runtime text security contract

How each flow runs, with diagrams, is described in [runtime-flows.md](runtime-flows.md).

Patronus runtime plugins protect **external text before it reaches the agent model**.
Each enabled surface uses the same text boundary across supported hosts. Users may explicitly disable a surface or pause a chat through the trusted dashboard or CLI settings; disabled surfaces do not grant scan approval. The default enables all three surfaces:

1. **User Prompt Input** — scan every non-empty user-authored text string or text block,
   excluding the `pii` category by default. `analysis.user_prompt_pii` explicitly opts it in; other configured categories remain active.
2. **Tool Results** — scan every non-empty externally returned text string or text block.
3. **MCP Results** — scan every non-empty `content[].text` block returned by an MCP tool.

These rules are unconditional:

- Text is scanned even when the same message or result also contains images,
  audio, binary attachments, structured data, or other media.
- Coverage never depends on a tool name such as `Bash` or `Read`.
- Coverage never depends on whether text parses as JSON.
- JSON-looking text remains one raw text value. Plugins must not parse it into
  keys and values before scanning.
- Envelope keys, paths, tool names, metadata, media bytes, and tool-call
  arguments are not scanner input.
- Tool requests are outside this runtime text contract and must not be scanned.
- Protection is fail-open for tool execution. Missing authentication, exhausted
  API usage, scanner startup failures, timeouts, and unavailable API responses
  must not prevent the agent from invoking the requested tool.
- When Patronus cannot complete a result scan, the original result remains
  available to the agent together with explicit degraded context. This does
  not grant approval: the agent must identify the content as unchecked and may
  continue the user's task with that limitation visible.
- Multiple non-empty text blocks retain their order and are submitted as raw strings;
  non-text blocks neither enter the scanner nor cause adjacent text to be
  skipped.
- If a host exposes an external result as one raw string projection instead of
  text blocks, scan that exact string unchanged. Do not parse or reconstruct it.
- A plugin must not claim a protected surface until a host mock proves the
  exact text is observable, enforcement tests prove the text reaches the
  scanner, and a real host test proves the installed integration preserves the
  boundary.

The required implementation order for each host is:

1. **See it:** capture the real hook/event shape and assert the exact extracted
   text with a host mock.
2. **Protect it:** gate the extracted raw text before the next model turn.
3. **Prove it:** run the installed host with clean, dangerous, mixed-media, and
   JSON-looking text cases.

Static repository scans and tool-request scanning do not count toward any of
the three runtime surfaces above.

A user prompt whose findings are only prompt injection or threat is still sent: the user wrote or pasted it deliberately. The user sees a warning, and the model is told to treat instructions inside pasted, quoted or external content as data. Prompts with DLP or PII findings, or a dangerous verdict without named findings, are blocked before they reach the model. Only a sensitive-data block offers `ignore_once`: resending the same message with that command within 15 minutes sends it once. Pasted quoting, trailing punctuation and whitespace around the command do not change the match, and a mismatched retry keeps the challenge.

Exact user messages `patronus off`, `patronus on` and `patronus status` are trusted local control commands. Only the user-input boundary may recognize them; they never come from tool/MCP results or substrings. Explicitly paused chats are outside the enabled scanning boundary until resumed.

## Redacted results and static audits

An enabled runtime result gate is sufficient for ordinary file reads. A separate
static audit is not a prerequisite: static reports contain metadata and cannot
be used as runtime result references. This avoids trapping the agent behind a
static PII finding with no redacted-content retrieval path.

Completed response scans with full coverage and only PII/DLP findings automatically
retrieve the scanner's redacted view. The native result gate and subsequent status
checks return `status=redacted` with usable masked text in `result`; they never
approve or release the original. Retrieval failures retain the dangerous receipt
and its manual `patronus_read_redacted` route. Pending, incomplete, and mixed
injection findings do not qualify for automatic privacy redaction. The same
behavior applies to the DeepSeek response gate and status tool. User prompts
retain their existing policy.

A finding without evidence spans covers the chunk that carried the verdict, not its whole field; every other chunk was classified on its own. `patronus_read_redacted` on a prompt-injection finding narrows it on this device only, never through the API: the region is halved, each half that is still flagged is halved again, and the middle half is tried once when an instruction crosses the cut. Cuts prefer the blank-line paragraph boundary nearest the middle, then a sentence or line boundary near it; a short region spanning several lines (an env file, CSV rows) is split between lines. Overlapping findings from different model stages share one region and one scan budget; separate regions have their own budgets, shared by their recursive splits. Before restoring a sibling, the proposed masked field must scan clean in context. Once that smaller mask is confirmed, restored siblings remain visible permanently: later failures, deadlines, exhausted budgets, or rejected finer masks retain the last verified mask. Parent or whole-field checks must never widen a mask over those approved siblings. If both halves lose a context-dependent signal and the middle cannot localize it, that finding cannot be narrowed. One deliberate exception widens a mask: a part that stays masked inside a hidden container (an HTML comment) masks the whole container, including restored siblings in it, because hidden text is not content for the user or the agent and its harmless-looking lead-in can carry the instruction without its payload. The original verdict, coverage, and findings remain unchanged; the redacted view is not a new whole-field approval, and the original is never released.

### Selective PII disclosure

A user can let the agent see selected PII types from one dangerous runtime
result, once, in Claude Code, Codex and DeepSeek Harness. Static `file_id`s keep
the masked view.

1. `patronus_read_redacted` with `scan_id` and `reveal_pii` (for example
   `["email", "ip_address"]`) returns `status=confirmation_required`, a
   `grant_id` and counts per type. It never returns values.
2. `patronus_reveal_pii` with `scan_id` and `grant_id` asks the user, naming the
   counts: "Reveal 3 email addresses and 2 IP addresses from this result to the
   AI agent once? The values will be sent to its model."
3. Only an approved call returns `status=redacted` with the confirmed PII
   visible and `disclosure={authorized_pii_types, user_confirmed: true}`.

How each host asks the user:

| Host | Approval | Delivery |
| --- | --- | --- |
| Claude Code | The PreToolUse hook arms the offer and returns `permissionDecision: "ask"` with the question. This forces Claude's permission dialog even when Patronus tools are pre-allowed. | The plugin's MCP server, only for an armed offer. |
| Codex | `.mcp.json` sets `approval_mode = "prompt"` for `patronus_reveal_pii`; Codex's PreToolUse rejects `ask`. The hook arms the offer and shows the question as a notice before Codex's MCP approval prompt. | Codex's MCP process has no session, so the PostToolUse hook replaces the placeholder result. A denied call never reaches it. |
| DeepSeek Harness | The tool calls the Harness approval seam with the question and acts only on `allowed-once`. `rejected`, `cancelled` and a missing answerer (`unavailable`) keep the mask. | The tool itself. |

Model arguments never carry a confirmation: a `confirmed` or `user_confirmed`
argument is rejected. In Claude and Codex the hook denies the call when the
permission mode would skip the prompt (anything but `default`, `acceptEdits` or
`plan`); `codex exec` reports `bypassPermissions` and is denied. The broker
releases nothing for an offer the hook did not arm, and a failing hook denies.
A host configuration that auto-approves the tool cannot be detected; the host's
approval prompt is the confirmation of record.

Only results whose every finding is PII qualify. With any prompt-injection,
DLP or threat finding, nothing becomes readable and the offer is
`nothing_to_reveal`. Within such a result only exact L1 evidence spans with a
type from the fixed list can be revealed. Other or unknown PII types and
chunk-level verdicts without evidence spans stay masked and win on overlap.
Card security codes and expiry dates are never revealable.

A grant is bound to the session, scan ID, original payload hash, scanner policy
fingerprint and the exact revealable locations shown for approval. It expires
after five minutes, a newer offer for the same result supersedes it, and it is
delivered once. The runtime builds the view directly from the hash-checked
original; the disclosed view is never stored or cached. The scan verdict,
`check` and `read_redacted` results are unchanged. The protocol journal records
requested types, grant state and the hook decision, never values.

Pending responses expose their current `job_status`. A queued response also
includes `wait_reason=scanner_queue` and `next_tool=patronus_check_result` with
explicit guidance that queue backpressure is neither failure nor expiry. Agents
must retain the scan ID and poll later; they must not rerun the source tool.

Static audits run independently of runtime worker startup and have a bounded
five-minute scan budget, covered by the native PreToolUse broker and host budgets.
Configuration failures return `configuration_unavailable` without exposing raw
process diagnostics; expiration remains `timeout`. An installed CLI must support
the active configuration, including `ark.model_dir` when configured.

Explicit URL/MCP audits use the API in every processing mode. URLs can use the
rate-limited anonymous identity; MCP audits remain authenticated. If quota,
authentication, network access, or the API is unavailable, the CLI audit reports failure.
The hook must fall open, preserve normal tool execution, and add degraded context;
an unavailable audit is never approval.
