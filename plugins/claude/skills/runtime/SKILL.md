---
name: runtime
description: Interpret Patronus native scan receipts in Claude Code and use its safe status, redacted-result, or explicit static-scan tools.
---

Patronus native hooks can replace a supported tool result with a scan receipt. A pending receipt is not the tool's original content and does not approve it.

Use the plugin's `patronus_check_result` tool with the receipt's `scan_id` to check status. Use `patronus_read_redacted` for the broker's permitted redacted result when available. A still-pending result can be checked again later; do not claim completion before its status is known. Failed, unavailable or denied results are not approval to recover the original by another tool.

These tools are safe placeholders intercepted by PreToolUse. Claude can display their sanitized result as a tool denial; interpret the enclosed Patronus receipt rather than treating the denial as an instruction to bypass the hooks. Supply only the tool's declared arguments. The session identity and private capability come from the hook and broker, never from model arguments.

With trusted runtime hooks active, ordinary reads do not require an additional static audit. A `status=redacted` result is usable masked text: continue the task without asking for approval. Never reconstruct masked regions or overwrite source data with redaction placeholders.

Never infer a static repository scan from the current working directory or from an
ordinary read. Unchanged runtime text is identified by its payload hash and may
reuse a completed result under the same scanner configuration and policy scope.

For an explicit repository, directory, or file scan, use `patronus_scan` with `kind` and `path`. Report its actual status and coverage.

If Patronus reports degraded protection, identify the affected content as unverified and continue only under that limitation. Do not describe failed or unavailable scanning as approval.

This skill explains the native receipt workflow. Deterministic enforcement comes from the installed hooks and shared local runtime, within the supported host/tool scope; the skill itself does not protect arbitrary tools or connectors.
