---
name: scan
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
The CLI resolves MCP configuration locally and sends only the public HTTPS
endpoint. It does not start stdio servers or forward private MCP credentials.
Scanning server metadata does not approve future responses or execute its tools.

Local scans text/files on this device and refuses URL/MCP API checks. `hybrid` keeps files and prompts local; runtime tool/MCP results of at most 1024 tokens stay local, larger results go to the API. API sends text to the API. URL/MCP checks use the API in Hybrid or API mode. Never silently change the configured mode.

If the native scan tool is unavailable, resolve the separately installed trusted CLI from `PATH`, outside the repository under inspection. Inspect `config print --format json`, then use `patronus-security-scanner scan KIND TARGET --format json`; for a named MCP entry add `--server NAME`. Missing CLI/setup is handled by `patronus-setup` when installation is requested.

Summarize status, supported category findings and complete/incomplete coverage. Return only safe report metadata; do not echo candidate content or process diagnostics. An `INCOMPLETE`, failed or pending scan never grants approval. Static file references are not runtime scan IDs. Runtime pending receipts use `patronus_check_result`; dangerous runtime receipts use `patronus_read_redacted`, without repeating the original operation.

An explicit URL scan does not automatically gate an unrelated connector's subsequent fetch. Only a verified deterministic runtime gate can protect that fetched text before model context.

Never invoke `support-us` unless the user explicitly requests it. Never fall back to a different provider silently.
