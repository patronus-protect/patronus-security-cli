---
name: patronus-security-scan
description: Check an explicitly requested file, directory, repository, public HTTPS URL or MCP server with Patronus, preserving scope and returning scan coverage and findings.
---

Use the native `patronus_scan` tool for explicit checks, keeping the user's scope:

Invoke this skill and the static scan tool only when the user explicitly asks for
that audit. Never infer a repository scan from the working directory, a file read,
or the presence of this skill. Runtime hooks scan only text that crosses their
prompt/tool/MCP result boundary.

- File: `{"kind":"file","path":"/absolute/path/file.ext"}`.
- Directory/repository: `{"kind":"directory","path":"/absolute/path"}` or `{"kind":"repo","path":"/absolute/repository"}`.
- URL: `{"kind":"url","path":"https://example.org/page"}`.
- Public MCP server: `{"kind":"mcp","path":"https://example.org/mcp"}`.
- MCP configuration: `{"kind":"mcp","path":"/absolute/config.json","server":"selected-name"}`. JSON `mcpServers` and TOML `mcp_servers` are supported. Select a name when several servers exist.

For that explicit audit, do not pre-read candidate files or fetch URLs yourself.
Pass a user-supplied relative or absolute path directly to `patronus_scan`; do not
locate, normalize, inspect, or validate it with file or shell tools first.
The CLI resolves MCP configuration locally and sends only the public HTTPS
endpoint. It does not start stdio servers or forward private MCP credentials.
Scanning server metadata does not approve future responses or execute its tools.

`local` scans text/files on this device. `hybrid` keeps prompts local; tool/MCP results and files of at most 2048 tokens stay local, larger ones go to the API. `api` sends text to the API. Explicit URL/MCP audits always use the API, including in `local` mode; this does not change the configured processing mode.

If the native scan tool is unavailable, resolve the separately installed trusted CLI from `PATH`, outside the repository under inspection. Inspect `config print --format json`, then use `patronus-security-scanner scan KIND TARGET --format json`; for a named MCP entry add `--server NAME`. Missing CLI/setup is handled by `patronus-setup` when installation is requested.

Summarize status, supported category findings and complete/incomplete coverage. Return only safe report metadata; do not echo candidate content or process diagnostics. An `INCOMPLETE`, failed or pending scan never grants approval. Patronus is fail-open for the user's underlying tool request: if an audit is unavailable because authentication, usage, network access or the API is unavailable, continue with the requested tool under the hook's degraded context and do not claim Patronus approved it. To read a masked document from a static finding, call `patronus_read_redacted` once with its `file_id`. Runtime pending receipts use `patronus_check_result` with `scan_id`; dangerous runtime receipts use `patronus_read_redacted` with `scan_id`, without repeating the original operation.

An explicit URL scan does not automatically gate an unrelated connector's subsequent fetch. Only a verified deterministic runtime gate can protect that fetched text before model context.

Never invoke `support-us` unless the user explicitly requests it. Never fall back to a different provider silently.
