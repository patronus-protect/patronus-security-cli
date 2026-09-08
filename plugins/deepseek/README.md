# Patronus Security for DeepSeek Harness

This package is the DeepSeek Harness plugin. It does not contain or install the Patronus scanner, Ark assets, Node.js, or `pnpm`.

## Requirements

- DeepSeek Harness CLI `dsh` from `@deepseek-ai/dsh@0.1.2-rc.1`, with the headless profile.
- Node.js as specified by this package's `engines` field and `pnpm` on `PATH` for Harness plugin management.
- The matching trusted `patronus-security-scanner` release installed separately on an absolute `PATH` entry.
- An explicit `local`, `api`, or `hybrid` scanner configuration. Prepare L2/L3 assets separately when those levels are enabled.

## Install and verify

Install and verify the supported Harness CLI if it is not already present:

```console
npm install --global @deepseek-ai/dsh@0.1.2-rc.1
dsh --version
```

Install from the released `.tgz`; a source checkout is not a release package:

```console
patronus-security-scanner integration deepseek install --profile headless --source /absolute/path/to/patronus-deepseek-security.tgz
patronus-security-scanner integration deepseek status --profile headless --format json
```

Restart the Harness after installation.

```console
patronus-security-scanner integration deepseek disable --profile headless
patronus-security-scanner integration deepseek enable --profile headless
patronus-security-scanner integration deepseek update --profile headless --source /absolute/path/to/patronus-deepseek-security.tgz
patronus-security-scanner integration deepseek uninstall --profile headless
```

The plugin gates external text and keeps a separate private runtime state per native session. It scans user-prompt text, tool-result text, and MCP `content[].text` before model continuation. It does not scan tool requests, paths, tool names, metadata, or media bytes. Dangerous originals remain unavailable; pending results use the supplied status workflow. JSON-looking text remains raw text.

Static file, directory, repository, URL, and MCP-server scans are explicit operations and are separate from runtime protection. A visible plugin entry does not prove enforcement; verify host visibility, enforcement, and installed-host behaviour before relying on it. The canonical contract is `docs/runtime-text-contract.md` in the source repository.

Never configure the plugin to execute a scanner binary from the repository being scanned. Licensed under Apache-2.0; see the `LICENSE` file included in this package.
