const assert=require('node:assert/strict');
const fs=require('node:fs');
const text=fs.readFileSync('plugins/codex-api/server/mcp_home.ts','utf8');
const html=JSON.parse(text.split('export const homeHtml = ')[1].trim().replace(/;$/,''));
assert.match(html,/patronus-security-scanner dashboard/);
assert.match(html,/does not read or change settings on your computer/);
assert.match(html,/data-open="https:\/\/github.com\/patronus-protect\/patronus-security-cli\/blob\/main\/INSTALL.md"/);
assert.match(html,/Install the CLI/);
console.log('PASS: hosted MCP explains local configuration and links to the official CLI installer');
