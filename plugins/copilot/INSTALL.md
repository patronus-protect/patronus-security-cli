# Install Patronus Security for GitHub Copilot CLI

These instructions are for an agent helping a user install the Copilot CLI integration.

1. Confirm that `patronus-security-scanner` and GitHub Copilot CLI (`copilot`) are installed.
2. Ask for permission to add a hook file to the user's Copilot configuration (`~/.copilot/hooks/patronus-security.json`) and an MCP server entry to `~/.copilot/mcp-config.json`.
3. Install through the trusted Patronus CLI; do not edit hook or plugin files directly:

   ```sh
   patronus-security-scanner integration copilot install
   ```

4. Verify the integration without reading credentials:

   ```sh
   patronus-security-scanner integration copilot status
   ```

5. Ask the user to start a new `copilot` session, then verify with `patronus status`.

Tell the user what is not covered (see [`README.md`](README.md)): the error text of a failed tool is only flagged with a warning; custom instructions, skills and attachments are not scanned; and the Copilot cloud coding agent is not covered. Also tell the user that in `copilot -p` and autopilot, Copilot denies risky shell commands and PII disclosures, because nobody can approve them there.

The user must complete browser authentication personally. Never request or
expose API keys, login tokens or anonymous identity cookies. If the CLI is not
installed, follow the repository's root [`INSTALL.md`](https://github.com/patronus-protect/patronus-security-cli/blob/main/INSTALL.md) first.
