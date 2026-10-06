---
name: patronus-api-setup
description: Connect the hosted Patronus API, explain account sign-in and open the account dashboard. Use for initial setup, authentication problems or usage questions.
---

Use the bundled hosted Patronus MCP at https://control.patronus.studio/api/mcp. Use its OAuth connection flow in the host; never ask users to paste passwords, access tokens or API keys into chat. Tool discovery alone does not prove sign-in. Complete authenticated work only after the host has connected the user's account. Do not run a billable scan merely to test authentication.

Explain that explicit scans send selected content to the Patronus API and consume the account allowance. This package does not provide automatic interception or pre-model protection. Offer the optional CLI/runtime workflow only when the user wants local repository access or runtime hooks.

For the account dashboard and usage, open https://control.patronus.studio with the available browser-opening tool. Let the user sign in there if needed. Do not invent usage figures: the current MCP has no usage tool. Dashboard sign-in and the host MCP connection are distinct sessions.

If OAuth connection fails, report the host's actual error and point to Patronus support. Do not substitute anonymous scan_text for the authenticated scan workflow. Do not modify local providers, install software or trust hooks during onboarding.
