// Contract check against the installed cursor-agent binary. The public CLI cannot run a scripted
// model without a Cursor login, so this test verifies the hook contract Patronus relies on directly
// in the shipped bundle: which events run, which fields they pass, and which outputs Cursor honours.
// A failure means Cursor changed its hook contract; re-check plugins/native/src/hosts/cursor.ts.
//
//   PATRONUS_CURSOR_BINARY=~/.local/bin/cursor-agent node --test plugins/cursor/tests/bundle-contract.test.mjs
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, realpathSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'

const binary = process.env.PATRONUS_CURSOR_BINARY ?? join(homedir(), '.local/bin/cursor-agent')
const available = existsSync(binary)
const bundle = available ? (() => {
  const root = dirname(realpathSync(binary))
  return readdirSync(root).filter(name => name.endsWith('.js')).map(name => readFileSync(join(root, name), 'utf8')).join('\n')
})() : ''
const pinned = readFileSync(new URL('../../../.github/release-host-versions.env', import.meta.url), 'utf8').match(/^CURSOR_RELEASE_VERSION=(.+)$/m)?.[1]
// Event enums are matched by shape, not name: the minifier renames them between releases.
const has = (pattern, message) => assert.ok(pattern.test(bundle), `${message} (pattern ${pattern})`)

test('cursor-agent version is reported against the release pin', { skip: !available && 'cursor-agent not installed' }, () => {
  const version = execFileSync(binary, ['--version'], { encoding: 'utf8', env: { PATH: process.env.PATH, HOME: homedir() } }).trim()
  assert.ok(pinned, 'CURSOR_RELEASE_VERSION is missing from .github/release-host-versions.env')
  if (version !== pinned) process.stdout.write(`# cursor-agent ${version} differs from the pinned ${pinned}\n`)
})

test('every event Patronus registers is executed by the local agent', { skip: !available && 'cursor-agent not installed' }, () => {
  const hooks = JSON.parse(readFileSync(new URL('../hooks/hooks.json', import.meta.url), 'utf8')).hooks
  for (const event of Object.keys(hooks)) has(new RegExp(`executeHookForStep\\([\\w$]+\\.[\\w$]+\\.${event}\\b`), `${event} is no longer executed`)
})

test('beforeReadFile passes file content and a deny withholds the read', { skip: !available && 'cursor-agent not installed' }, () => {
  has(/executeHookForStep\([\w$]+\.[\w$]+\.beforeReadFile,\{\.\.\.\w+,content:\w+,file_path:/, 'beforeReadFile no longer receives content')
  has(/"deny"===\w+\?\.permission\)\{const \w+=\w+\("File read",\w+\.user_message\);throw/, 'a beforeReadFile deny no longer blocks the read with user_message')
  has(/\$\{\w+\} was blocked by a hook: \$\{\w+\}/, 'the blocked-read message format changed')
})

test('postToolUse passes tool_output and honours updated_mcp_tool_output for MCP tools only', { skip: !available && 'cursor-agent not installed' }, () => {
  has(/executeHookForStep\([\w$]+\.[\w$]+\.postToolUse,\{\.\.\.\w+,tool_name:\w+,tool_input:\w+,tool_output:/, 'postToolUse no longer receives tool_output')
  has(/void 0!==\w+\?\.updated_mcp_tool_output/, 'updated_mcp_tool_output is no longer honoured')
  has(/tool_name:`MCP:\$\{|`MCP:\$\{\w+\.toolName\}`/, 'MCP tool names are no longer prefixed with MCP:')
  // Non-MCP results only take additional_context. If this changes, shell output could be replaced too.
  has(/\.[\w$]+\.postToolUse,\w+\?\.additional_context\)/, 'postToolUse additional_context handling changed')
})

test('shell results carry output; Grep and Fetch still expose only metadata', { skip: !available && 'cursor-agent not installed' }, () => {
  has(/createSuccessOutput:\(\w+,\w+\)=>\(\{output:\w+\.getOutput\(\),exitCode:/, 'Shell tool_output no longer has {output, exitCode}')
  // Grep's hook output is {pattern, success}; the tool name is set through a minified constant.
  has(/createSuccessOutput:\w+=>\(\{pattern:\w+\.pattern,success:!0\}\)/, 'Grep output shape changed: it may now carry content Patronus should scan')
  assert.ok(!/createSuccessOutput:[^;]{0,120}pattern:\w+\.pattern,(?:matches|results|content|lines)/.test(bundle), 'Grep output now carries matches: scan them in postToolUse')
  has(/createSuccessOutput:\(\w+,\w+\)=>"success"===\w+\.result\.case\?\{url:\w+\.url,status_code:/, 'Fetch output shape changed: it may now carry content Patronus should scan')
})

test('beforeSubmitPrompt passes the prompt and honours continue', { skip: !available && 'cursor-agent not installed' }, () => {
  has(/\.[\w$]+\.beforeSubmitPrompt,\{[^}]*prompt:\w+\.prompt/, 'beforeSubmitPrompt no longer receives prompt')
  has(/case:"beforeSubmitPrompt",value:new \w+\.\w+\(\{continue:\w+\?\.continue,userMessage:\w+\?\.user_message/, 'beforeSubmitPrompt continue/user_message handling changed')
})

test('hooks get the conversation identity and workspace roots; plugin hooks get CURSOR_PLUGIN_ROOT', { skip: !available && 'cursor-agent not installed' }, () => {
  // session_id may be absent (Patronus falls back to conversation_id); the workspace stays the first root.
  has(/session_id:\w+\},hook_event_name:\w+,cursor_version:[^,]+,workspace_roots:\[(?:\.\.\.new Set\(\[)?this\.workspacePath[,\]]/, 'common hook fields changed')
  has(/\w+\.session_id\?\?\w+\.conversation_id/, 'session_id no longer falls back to conversation_id')
  has(/"CURSOR_PLUGIN_ROOT"/, 'CURSOR_PLUGIN_ROOT is no longer provided to plugin hooks')
  has(/\.cursor-plugin\/plugin\.json/, 'Cursor plugin manifests are no longer discovered')
})
