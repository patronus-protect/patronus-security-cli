# Patronus Security for Claude Code

The easiest installation is the Patronus onboarding flow. It detects Claude Code, downloads this plugin from the matching public release, installs it, and enables its hooks:

```sh
patronus-security-scanner onboarding
```

If the Patronus CLI is already configured, install only the Claude Code plugin with:

```sh
patronus-security-scanner integration claude install
```

Restart Claude Code after installation. Try:

> Check this repository with Patronus.

> Patronus status.

The plugin automatically checks user prompts, hook-visible tool-result text and MCP text blocks before model continuation. Dangerous originals remain unavailable; paths, tool requests, metadata and media bytes are outside this text boundary.

Open `patronus-security-scanner dashboard` to review activity and configuration. A supported Claude Code installation, Node.js 22.19 or newer, and the matching Patronus CLI release are required.

Licensed under Apache-2.0. The release archive includes `LICENSE` and `THIRD_PARTY_NOTICES.md`.
