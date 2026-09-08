import assert from 'node:assert/strict'
import test from 'node:test'
import { codexExternalText, codexExternalTextPayload } from '../src/hosts/codex.ts'
import type { HookInput } from '../src/types.ts'

const input = (event: string, extra: Partial<HookInput> = {}): HookInput => ({
  hook_event_name: event,
  session_id: 'codex-text-731',
  cwd: '/private/tmp',
  ...extra,
})

test('Codex extracts the raw user prompt without media or envelope data', () => {
  const value = input('UserPromptSubmit', {
    prompt: '{"task":"keep this exact JSON text"}',
    images: [{ type: 'image', data: 'PRIVATE-IMAGE-731' }],
    model: 'PRIVATE-MODEL-731',
  })
  assert.deepEqual(codexExternalText('UserPromptSubmit', value), ['{"task":"keep this exact JSON text"}'])
  assert.equal(codexExternalTextPayload('UserPromptSubmit', value), '{"task":"keep this exact JSON text"}')
})

test('Codex extracts every ordered MCP content text block and nothing else', () => {
  const value = input('PostToolUse', {
    tool_name: 'mcp__fixture__mixed',
    tool_response: {
      content: [
        { type: 'text', text: 'first' },
        { type: 'image', data: 'PRIVATE-IMAGE-731', mimeType: 'image/png' },
        { type: 'text', text: '{"second":"unchanged"}' },
      ],
      structuredContent: { private: 'PRIVATE-STRUCTURED-731' },
      _meta: { private: 'PRIVATE-METADATA-731' },
    },
  })
  assert.deepEqual(codexExternalText('PostToolUse', value), ['first', '{"second":"unchanged"}'])
  assert.deepEqual(codexExternalTextPayload('PostToolUse', value), ['first', '{"second":"unchanged"}'])
})

test('Codex treats a plain tool result as one unchanged raw text value', () => {
  const value = input('PostToolUse', {
    tool_name: 'AnyToolName',
    tool_response: '{"stdout":"still one external text value"}',
  })
  assert.deepEqual(codexExternalText('PostToolUse', value), ['{"stdout":"still one external text value"}'])
  assert.equal(codexExternalTextPayload('PostToolUse', value), '{"stdout":"still one external text value"}')
})

test('Codex never treats tool requests or wrapper-only results as external text', () => {
  assert.deepEqual(codexExternalText('PreToolUse', input('PreToolUse', {
    tool_input: { command: 'PRIVATE-REQUEST-731' },
  })), [])
  assert.deepEqual(codexExternalText('PostToolUse', input('PostToolUse', {
    tool_response: { content: [{ type: 'image', data: 'PRIVATE-IMAGE-731' }], _meta: { text: 'PRIVATE-METADATA-731' } },
  })), [])
})
