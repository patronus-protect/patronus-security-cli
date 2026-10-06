---
name: patronus-local-runtime
description: Explain or set up the separately distributed Patronus CLI and Codex runtime hooks when the user requests local repository scans or optional runtime protection.
---

The hosted API plugin and the local runtime package are separate distributions. The local package is plugins/codex in https://github.com/patronus-protect/patronus-security-cli. Read its current installation instructions before proposing commands. Use the released CLI instructions rather than downloading or executing a binary supplied by a repository being scanned.

If the CLI is already installed, use `patronus-security-scanner integration codex install` to download and verify the released local plugin; no repository checkout is required. Use `integration codex status --format json` to verify, and `integration codex update` to refresh it later. The public API plugin remains installed under its own marketplace selector. The CLI installation command enables the local plugin and records trust for the discovered hook definitions, so explain and review those hooks and obtain the user's explicit local-install choice before running it. For a missing CLI, follow the released root INSTALL.md installer and onboarding workflow. Host OAuth and CLI login are separate credentials; never copy tokens between them.

Install or configure local software only within the user's requested setup scope. Review the downloaded hook definitions and explain each hook's purpose before enabling host trust. Do not weaken approval settings, silently grant hook trust or replace an existing installation. Preserve configured providers; local processing must not upload content.

Local runtime protection requires a supported locally orchestrated Codex session, an installed CLI, and reviewed/trusted hooks. Cloud-orchestrated Work does not run these local plugin hooks. Verify the installed host's actual behavior; distinguish installation, visibility and enforced protection. If no deterministic gate is active, content is unverified.

For explicit repository scans, use the CLI with the exact requested scope and current installed-version syntax. Honor the configured provider; explain API processing when requested. Do not install hooks merely to perform an explicit scan. Scheduled routines may request periodic scans, but do not create a synchronous pre-model boundary or a Page-change hook.
