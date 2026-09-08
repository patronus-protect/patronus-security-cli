import test from 'node:test';
import assert from 'node:assert/strict';
import { claudeExternalText, mapClaude, supportsClaudeResponse } from '../../native/src/hosts/claude.ts';

const input = (tool_name, tool_response) => ({
  hook_event_name: 'PostToolUse', session_id: 'trusted-session', cwd: '/tmp',
  tool_name, tool_use_id: 'call-1', tool_response,
});

test('request denial and intercepted safe placeholder results use only safe feedback', () => {
  assert.deepEqual(mapClaude('PreToolUse', { kind: 'deny', text: 'SAFE' }), {
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'SAFE' },
  });
  assert.deepEqual(mapClaude('PreToolUse', { kind: 'replace', text: 'SAFE' }),
    mapClaude('PreToolUse', { kind: 'deny', text: 'SAFE' }));
});

test('Bash replacement preserves schema but never spreads original fields', () => {
  const original = { stdout: 'RAW', stderr: 'RAW', interrupted: false, isImage: false, extra: 'RAW' };
  const hook = input('Bash', original);
  assert.equal(supportsClaudeResponse(hook), true);
  assert.deepEqual(mapClaude('PostToolUse', { kind: 'replace', text: 'PENDING' }, hook), {
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      updatedToolOutput: { stdout: 'PENDING', stderr: '', interrupted: false, isImage: false },
    },
  });
});

test('external text extraction is tool-name independent and preserves raw JSON text', () => {
  assert.deepEqual(claudeExternalText('PostToolUse', input('Anything', 'RAW')), ['RAW']);
  assert.deepEqual(claudeExternalText('PostToolUse', input('Anything', [
    { type: 'image', data: 'PRIVATE-IMAGE' },
    { type: 'text', text: '{"raw":true}' },
    { type: 'text', text: 'SECOND' },
  ])), ['{"raw":true}', 'SECOND']);
  assert.deepEqual(claudeExternalText('PostToolUse', input('Anything', {
    content: [{ type: 'text', text: 'MCP-TEXT' }, { type: 'image', data: 'PRIVATE-IMAGE' }],
    structuredContent: { private: 'METADATA' },
  })), ['MCP-TEXT']);
  assert.deepEqual(claudeExternalText('PostToolUseFailure', {
    ...input('Anything', undefined), hook_event_name: 'PostToolUseFailure', error: 'RAW-FAILURE-TEXT',
  }), ['RAW-FAILURE-TEXT']);
});

test('generic text and mixed-media results replace text without depending on a tool name', () => {
  const plain = input('Anything', 'RAW');
  assert.equal(supportsClaudeResponse(plain), true);
  assert.deepEqual(mapClaude('PostToolUse', { kind: 'replace', text: 'SAFE' }, plain), {
    hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: 'SAFE' },
  });

  const mixed = input('Anything', [
    { type: 'image', data: 'IMAGE', mimeType: 'image/png' },
    { type: 'text', text: 'RAW' },
    { type: 'text', text: 'RAW-2' },
  ]);
  assert.equal(supportsClaudeResponse(mixed), true);
  assert.deepEqual(mapClaude('PostToolUse', { kind: 'replace', text: 'SAFE' }, mixed), {
    hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: [
      { type: 'image', data: 'IMAGE', mimeType: 'image/png' },
      { type: 'text', text: 'SAFE' },
    ] },
  });
});

test('Read text replacement uses a complete safe file shape without original metadata', () => {
  const hook = input('Read', { type: 'text', file: {
    filePath: '/RAW', content: 'RAW', numLines: 1, startLine: 10, totalLines: 100,
  } });
  assert.equal(supportsClaudeResponse(hook), true);
  assert.deepEqual(mapClaude('PostToolUse', { kind: 'replace', text: 'PENDING\nPOLL' }, hook), {
    hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: {
      type: 'text', file: { filePath: '[Patronus]', content: 'PENDING\nPOLL', numLines: 2, startLine: 1, totalLines: 2 },
    } },
  });
});

test('media-only responses have no external text to scan or replace', () => {
  for (const hook of [
    input('Bash', { isImage: true }),
    input('Read', { type: 'image', file: { base64: 'RAW' } }),
    input('mcp__fixture__read', [{ type: 'image', data: 'RAW', mimeType: 'image/png' }]),
  ]) {
    assert.equal(supportsClaudeResponse(hook), false);
    assert.deepEqual(mapClaude('PostToolUse', { kind: 'replace', text: 'STOP' }, hook), { continue: false, stopReason: 'STOP' });
  }
});

test('PostToolBatch is the final native stop point for a quarantined session', () => {
  assert.deepEqual(mapClaude('PostToolBatch', { kind: 'stop', text: 'QUARANTINED' }), {
    continue: false, stopReason: 'QUARANTINED',
  });
});
