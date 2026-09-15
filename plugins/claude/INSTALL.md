# Install Patronus Security for Claude Code

These instructions are for an agent helping a user install the Claude Code plugin.

1. Confirm that `patronus-security-scanner` and Claude Code are installed.
2. Ask for permission to modify the user's Claude Code plugin configuration.
3. Install through the trusted Patronus CLI; do not edit plugin files directly:

   ```sh
   patronus-security-scanner integration claude install
   ```

4. Verify the integration without reading credentials:

   ```sh
   patronus-security-scanner integration claude status
   ```

5. Ask the user to restart Claude Code, then verify with `Patronus status`.

The user must complete browser authentication personally. Never request or
expose API keys, login tokens or anonymous identity cookies. If the CLI is not
installed, follow the repository's root [`INSTALL.md`](../../INSTALL.md) first.
