# Patronus Security for DeepSeek Harness

Install the supported DeepSeek Harness CLI first:

```sh
npm install --global @deepseek-ai/dsh@0.1.2-rc.1
```

Then run Patronus onboarding. It detects `dsh`, downloads the matching Patronus package, installs it into the `headless` profile, and enables protection automatically:

```sh
patronus-security-scanner onboarding
```

If the Patronus CLI is already configured, install only the DeepSeek plugin with:

```sh
patronus-security-scanner integration deepseek install
```

Restart the Harness after installation. Try:

> Check this repository with Patronus.

> Patronus status.

The plugin automatically checks user prompts, tool-result text and MCP text blocks before model continuation. Each native session gets private scanner state. Dangerous originals remain unavailable; paths, tool requests, metadata and media bytes are outside this text boundary.

Open `patronus-security-scanner dashboard` to review activity and configuration. Node.js and `pnpm` must satisfy the package requirements.

Licensed under Apache-2.0. The package includes `LICENSE` and `THIRD_PARTY_NOTICES.md`.
