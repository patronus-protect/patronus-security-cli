---
name: patronus-runtime
description: Handle Patronus runtime receipts and continue with approved or redacted results.
---

Use the native `patronus` MCP tools when this plugin's trusted hooks are active.

With active, trusted runtime hooks, read files through the protected tool path. The hook scans the returned text before it reaches the model; do not require a separate static scan before every read. Static scans are explicit audits, return metadata only, and do not supply runtime scan IDs or redacted file content. A static finding is not a reason to abandon a read through the protected runtime boundary.

Never infer a static repository scan from the current working directory or from an
ordinary read. Unchanged runtime text is identified by its payload hash and may
reuse a completed result under the same scanner configuration and policy scope.

A `status=redacted` response contains the usable masked text in `result`. Continue the user's task with that text without asking for approval. Do not reconstruct masked regions or write redaction placeholders back over existing source data. For a dangerous runtime receipt with `redacted_available=true`, call `patronus_read_redacted` with its `scan_id`. Failed or incomplete scans never authorize original content.

A pending receipt means the source tool already executed. Follow the receipt's instructions, continue independent work and call `patronus_check_result` with its `scan_id`. Do not repeat the source action to recover its result. Approved responses can return their verified original; dangerous responses offer only `patronus_read_redacted`. There is no dangerous-original bypass.

Codex delivers these receipts, including successful Patronus retrievals, as native hook denial feedback. Read the enclosed status instead of assuming the original action must be retried. Never supply a session identifier or capability in tool arguments; the native hook provides session attribution.

If the tool reports that native hooks did not handle its call, stop and check hook installation and trust. Do not silently disable hooks, switch providers, or invoke a scanner supplied by the target repository. Protection applies only to the tested native tool paths; external fetches, metadata, attachments and other context sources require their own verified boundary.

After a plugin update or hook-trust repair, an already running parent task can retain the old trust state and pass it to newly spawned subagents. A fresh CLI status checks newly loaded tasks, not that existing runtime. Reload the affected parent task or restart the host before retrying the existing receipt; do not rerun the source action.
