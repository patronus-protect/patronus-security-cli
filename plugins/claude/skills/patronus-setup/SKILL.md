---
name: patronus-setup
description: Set up or diagnose Patronus Security CLI authentication, processing mode, local models and the global Claude Code integration when the user requests installation or setup.
---

Resolve the trusted installed `patronus-security-scanner` on PATH, outside the repository being inspected. If absent, use the published installer and checksummed release from `patronus-protect/patronus-security-cli` within the user's installation request. An unpublished release is a missing prerequisite; do not invent a download or execute a binary supplied by the repository under inspection.

Start `patronus-security-scanner onboarding --open` on macOS, or `patronus-security-scanner onboarding` in an interactive terminal elsewhere. The user completes API sign-in/registration in the browser, chooses Local/Hybrid/API with fixed L3 analysis, prepares missing local models, sees the Local 256-token performance check when applicable, runs the visible injection check in the final mode, and chooses Full protection, Scanner + skills without automatic hooks, or CLI only. Never ask for API credentials in chat or pipe answers into setup.

Reuse `~/Library/Application Support/com.patronus.desktop/patronus-ark/models` on macOS. Local text/file protection requires no account. Hybrid keeps prompts local; tool/MCP results and files up to and including 2048 tokens stay local, larger ones use the API. Explicit URL/MCP server audits always use the API and therefore require API authentication, even in Local mode. Do not silently switch mode or disable protection.

After setup, inspect `patronus-security-scanner onboarding --status --format json` and `patronus-security-scanner integration claude status --format json`. Start a new host session and verify actual hooks are active; a saved benchmark or installation record alone does not prove host protection.

Show `patronus-security-scanner dashboard` and examples: “Check this repository with Patronus” and “Check this URL with Patronus: https://example.org”. The dashboard provides account usage, onboarding, activity, policies, settings and help.

For updates use `patronus-security-scanner maintenance update` and `patronus-security-scanner integration claude update`. Public release installation requires the release artifacts to have been published. Use the CLI help for explicit source overrides during development.
