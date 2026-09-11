# Patronus Runtime Protection shared runtime

This directory contains the shared Patronus Runtime Protection implementation used by the Codex and Claude Code integrations. Consumers do not install it directly.

Install Patronus with `install.sh`, complete `patronus-security-scanner onboarding`, and select the agent hosts you want to protect. The CLI downloads and installs the matching public release automatically.

The runtime accepts only the external text defined in `docs/runtime-text-contract.md` and requires a separately installed trusted Patronus Security CLI. It rejects repository-local scanner executables and incompatible runtime settings.

Licensed under Apache-2.0.
