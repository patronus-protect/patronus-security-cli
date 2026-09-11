# Runtime text security contract

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
