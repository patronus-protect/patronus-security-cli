# Install Patronus Security for Cursor

These instructions are for an agent helping a user install the Cursor integration.

1. Confirm that `patronus-security-scanner` and Cursor (the IDE or the `cursor-agent` CLI) are installed.
2. Ask for permission to modify the user's Cursor hooks (`~/.cursor/hooks.json`) and MCP configuration (`~/.cursor/mcp.json`).
3. Install through the trusted Patronus CLI; do not edit hook or plugin files directly:

   ```sh
   patronus-security-scanner integration cursor install
   ```

4. Verify the integration without reading credentials:

   ```sh
   patronus-security-scanner integration cursor status
   ```

5. Ask the user to restart Cursor (or start a new `cursor-agent` session), then verify with `patronus status`.

Tell the user that Cursor protection is partial: shell output is only warned about, and Grep, web fetch
and MCP resource results are not scanned (see [`README.md`](README.md)).

The user must complete browser authentication personally. Never request or
expose API keys, login tokens or anonymous identity cookies. If the CLI is not
installed, follow the repository's root [`INSTALL.md`](../../INSTALL.md) first.
