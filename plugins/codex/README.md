# Patronus Security for Codex

This archive contains the Codex plugin only. It does not contain or install the Patronus scanner, Ark assets, or Node.js.

## Requirements

- A supported Codex installation.
- Node.js 22.19 or newer.
- The matching trusted `patronus-security-scanner` release installed separately on an absolute `PATH` entry.
- An explicit `local`, `api`, or `hybrid` scanner configuration. Prepare L2/L3 assets separately when those levels are enabled.

## Install and verify

Extract the Codex plugin archive, then run:

```console
patronus-security-scanner integration codex install --source /absolute/path/to/extracted-codex-archive
patronus-security-scanner integration codex status --format json
```

Restart Codex. Ask `Scan this repository with Patronus Ark`, or invoke `$patronus-security-scan` with `repo .`, `directory PATH`, or `file PATH`.

```console
patronus-security-scanner integration codex disable
patronus-security-scanner integration codex enable
patronus-security-scanner integration codex update
patronus-security-scanner integration codex uninstall
```

The plugin includes native hooks, an MCP definition, runtime/static-scan skills, and a bundled JavaScript adapter. A manifest or visible tool does not prove protection. `status` must report the required hooks installed, enabled, reachable, and trusted. Start a new Codex task after lifecycle changes.

The runtime scans user-prompt text, tool-result text, and MCP `content[].text` before model continuation. It does not scan tool requests, paths, tool names, metadata, or media bytes. Dangerous originals remain unavailable; pending results use the supplied status workflow. JSON-looking text remains raw text. The full contract is `docs/runtime-text-contract.md` in the source repository.

Static repository scans are separate and return bounded coverage/finding metadata without adding source files to model context. Never point `PATRONUS_SCANNER_BIN` at a binary inside the repository being scanned.

Licensed under Apache-2.0; see the `LICENSE` file included in this archive.
