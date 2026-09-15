# Install Patronus Security for DeepSeek Harness

These instructions are for an agent helping a user install the DeepSeek Harness plugin.

1. Confirm that `patronus-security-scanner`, Node.js 22.19 or newer and the
   supported DeepSeek Harness are installed.
2. Ask before installing global npm packages or modifying the user's Harness
   profile. If Harness is missing, install the supported release:

   ```sh
   npm install --global @deepseek-ai/dsh@0.1.2-rc.1
   ```

3. Install through the trusted Patronus CLI; do not edit the profile directly:

   ```sh
   patronus-security-scanner integration deepseek install
   ```

4. Verify the host and integration without reading credentials:

   ```sh
   dsh --version
   patronus-security-scanner integration deepseek status
   ```

5. Ask the user to restart the Harness, then verify with `Patronus status`.

The user must complete browser authentication personally. Never request or
expose API keys, login tokens or anonymous identity cookies. If the CLI is not
installed, follow the repository's root [`INSTALL.md`](../../INSTALL.md) first.
