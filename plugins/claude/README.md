# Patronus Security for Claude Code

This archive contains the Claude Code plugin only. It does not contain or install the Patronus scanner, Ark assets, or Node.js.

## Requirements

- A supported Claude Code installation.
- Node.js 22.19 or newer.
- The matching trusted `patronus-security-scanner` release installed separately on an absolute `PATH` entry.
- An explicit `local`, `api`, or `hybrid` scanner configuration. Prepare L2/L3 assets separately when those levels are enabled.

## Install and verify

Extract the Claude plugin archive, then run:

```console
patronus-security-scanner integration claude install --source /absolute/path/to/extracted-claude-archive
patronus-security-scanner integration claude status --format json
```

Restart Claude Code. Run `/patronus-security:scan repo .` for the first static scan. For a one-off development load, Claude also supports `claude --plugin-dir /absolute/path/to/plugins/claude`; do not combine this plugin with `--strict-mcp-config`, which excludes its MCP configuration.

```console
patronus-security-scanner integration claude disable
patronus-security-scanner integration claude enable
patronus-security-scanner integration claude update
patronus-security-scanner integration claude uninstall
```

Use the same `--scope user|project|local` chosen at installation. Uninstall also accepts `--keep-data`. A manifest or tool listing alone does not prove protection; verify installed and enabled hook status after every lifecycle change.

The runtime scans the exact user prompt, hook-visible tool-result and tool-error text, and MCP text blocks before model continuation. It does not scan tool requests, paths, tool names, metadata, or media bytes. Dangerous originals remain unavailable; JSON-looking text remains raw text. Host surfaces that do not invoke the hooks are outside this protection boundary. The full contract is `docs/runtime-text-contract.md` in the source repository.

Never point `PATRONUS_SCANNER_BIN` at a binary inside the repository being scanned. Licensed under Apache-2.0; see the `LICENSE` file included in this archive.
