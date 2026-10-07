# Patronus for Activepieces

Native piece with secret-text authentication and Submit Scan / Get Scan Result
actions. Uses `@activepieces/pieces-framework` 0.32.0 and the current
`context.auth.secret_text` connection shape. Minimum platform release: 0.95.1;
the Node.js runtime must support version 22 or newer.

Build/package from [the parent directory](../README.md). Where private pieces are
supported, open **Platform Admin → Catalogue → Pieces → Install Piece → Upload
File** and upload `patronus-protect-piece-patronus-0.1.1.tgz`. This is the platform's
[private tarball installation flow](https://www.activepieces.com/docs/admin-guide/guides/manage-pieces).
Access depends on the instance/edition; this change does not publish to the
community catalogue.

Create a Patronus connection with an account API key carrying `scan:write` and
`scan:read`. Validation reads a missing job to test read access without a scan.
Add Submit Scan, select Text / Public HTTPS URL / Public MCP Server, and map
Content. Map each returned public job ID into Get Scan Result; delay/repeat with
a bounded loop for accepted/running jobs. Use a flow branch to enforce
[the completed-result policy](../README.md#workflow-behavior) before any LLM step.

The patched framework and its runtime dependencies are bundled, so a fresh installation cannot pull expr-eval 2.0.2 back in. Errors fail the action with a sanitized message. This piece sends selected
content to Patronus and is not an automatic interception hook. The patched framework is bundled into the piece; see the parent README for the dependency audit.

## Guard Input: connect directly before the LLM

Choose **Guard Input** and map the exact assembled RAG/prompt text into Content.
The step submits and polls internally, then releases only fully approved text.
Map the output `text` into the downstream LLM; in Dify use `protected_text`.
Blocked, review, incomplete, quota and timeout results stop the step without
returning the original input. Keep stop-on-error and do not use a source fallback.

The older Submit/Get actions are diagnostic operations. For the directly
connected protection path use Guard Input. See [the shared flow and test guide](../README.md#connect-rag--llm-input).
