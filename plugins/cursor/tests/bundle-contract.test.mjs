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
const has = (pattern, message) => assert.ok(pattern.test(bundle), `${message} (pattern ${pattern})`)

test('cursor-agent version is reported against the release pin', { skip: !available && 'cursor-agent not installed' }, () => {
  const version = execFileSync(binary, ['--version'], { encoding: 'utf8', env: { PATH: process.env.PATH, HOME: homedir() } }).trim()
  assert.ok(pinned, 'CURSOR_RELEASE_VERSION is missing from .github/release-host-versions.env')
  if (version !== pinned) process.stdout.write(`# cursor-agent ${version} differs from the pinned ${pinned}\n`)
})

test('every event Patronus registers is executed by the local agent', { skip: !available && 'cursor-agent not installed' }, () => {
  const hooks = JSON.parse(readFileSync(new URL('../hooks/hooks.json', import.meta.url), 'utf8')).hooks
  for (const event of Object.keys(hooks)) has(new RegExp(`executeHookForStep\\(\\w+\\._E\\.${event}\\b`), `${event} is no longer executed`)
})

test('beforeReadFile passes file content and a deny withholds the read', { skip: !available && 'cursor-agent not installed' }, () => {
  has(/executeHookForStep\(\w+\._E\.beforeReadFile,\{\.\.\.\w+,content:\w+,file_path:/, 'beforeReadFile no longer receives content')
  has(/"deny"===\w+\?\.permission\)\{const \w+=\w+\("File read",\w+\.user_message\);throw/, 'a beforeReadFile deny no longer blocks the read with user_message')
  has(/\$\{\w+\} was blocked by a hook: \$\{\w+\}/, 'the blocked-read message format changed')
})

test('postToolUse passes tool_output and honours updated_mcp_tool_output for MCP tools only', { skip: !available && 'cursor-agent not installed' }, () => {
  has(/executeHookForStep\(\w+\._E\.postToolUse,\{\.\.\.\w+,tool_name:\w+,tool_input:\w+,tool_output:/, 'postToolUse no longer receives tool_output')
  has(/void 0!==\w+\?\.updated_mcp_tool_output/, 'updated_mcp_tool_output is no longer honoured')
  has(/tool_name:`MCP:\$\{|`MCP:\$\{\w+\.toolName\}`/, 'MCP tool names are no longer prefixed with MCP:')
  // Non-MCP results only take additional_context. If this changes, shell output could be replaced too.
  has(/_E\.postToolUse,\w+\?\.additional_context\)/, 'postToolUse additional_context handling changed')
})

test('shell results carry output; Grep and Fetch still expose only metadata', { skip: !available && 'cursor-agent not installed' }, () => {
  has(/createSuccessOutput:\(\w+,\w+\)=>\(\{output:\w+\.getOutput\(\),exitCode:/, 'Shell tool_output no longer has {output, exitCode}')
  has(/toolName:"Grep"[^]{0,3000}?createSuccessOutput:\w+=>\(\{pattern:\w+\.pattern,success:!0\}\)/, 'Grep output shape changed: it may now carry content Patronus should scan')
  has(/createSuccessOutput:\(\w+,\w+\)=>"success"===\w+\.result\.case\?\{url:\w+\.url,status_code:/, 'Fetch output shape changed: it may now carry content Patronus should scan')
})

test('beforeSubmitPrompt passes the prompt and honours continue', { skip: !available && 'cursor-agent not installed' }, () => {
  has(/_E\.beforeSubmitPrompt,\{[^}]*prompt:\w+\.prompt/, 'beforeSubmitPrompt no longer receives prompt')
  has(/case:"beforeSubmitPrompt",value:new \w+\.\w+\(\{continue:\w+\?\.continue,userMessage:\w+\?\.user_message/, 'beforeSubmitPrompt continue/user_message handling changed')
})

test('hooks get the conversation identity and workspace roots; plugin hooks get CURSOR_PLUGIN_ROOT', { skip: !available && 'cursor-agent not installed' }, () => {
  has(/session_id:\w+\},hook_event_name:\w+,cursor_version:[^,]+,workspace_roots:\[this\.workspacePath\]/, 'common hook fields changed')
  has(/"CURSOR_PLUGIN_ROOT"/, 'CURSOR_PLUGIN_ROOT is no longer provided to plugin hooks')
  has(/\.cursor-plugin\/plugin\.json/, 'Cursor plugin manifests are no longer discovered')
})
