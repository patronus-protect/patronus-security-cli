import assert from 'node:assert/strict'
import test from 'node:test'
import { handleHook as runHook } from '../src/hooks.ts'

const noProtocol = async (_config: unknown, _request: unknown, run: () => Promise<any>) => run()
const handleHook: typeof runHook = (host, event, value, overrides, rpc) => runHook(host, event, value, overrides, rpc, noProtocol)

const base = { session_id: 'native-session-731', cwd: '/private/tmp', tool_name: 'Bash', tool_use_id: 'call-731', tool_input: { command: 'true' } }
const input = (event: string, extra = {}) => ({ ...base, hook_event_name: event, ...extra })

test('ordinary tool requests are outside the runtime text contract for every host', async () => {
  const calls: unknown[] = []
  const rpc = async (config: unknown, request: unknown) => { calls.push({ config, request }); return { scan_id: 'scan-731', status: 'approved' } }
  assert.deepEqual(await handleHook('codex', 'PreToolUse', input('PreToolUse'), {}, rpc), {})
  assert.deepEqual(await handleHook('claude', 'PreToolUse', input('PreToolUse'), {}, rpc), {})
  assert.equal(calls.length, 0)
})

test('Codex pending response replaces the original with a receipt', async () => {
  const result: any = await handleHook('codex', 'PostToolUse', input('PostToolUse', { tool_response: 'RAW-CANARY-731' }), {}, async () => ({ scan_id: 'scan-731', status: 'pending' }))
  assert.equal(result.decision, 'block')
  assert.equal(JSON.parse(result.reason).scan_id, 'scan-731')
  assert(!JSON.stringify(result).includes('RAW-CANARY-731'))
  assert(result.reason.includes('patronus_check_result'))
})

test('retrieval uses native session identity and never executes the MCP placeholder', async () => {
  let config: any, request: any
  const result: any = await handleHook('codex', 'PreToolUse', input('PreToolUse', { tool_name: 'mcp__patronus__patronus_check_result', tool_input: { scan_id: 'scan-731' } }), {}, async (c, r) => {
    config = c; request = r; return { scan_id: 'scan-731', status: 'approved', result: 'APPROVED-DOCUMENT' }
  })
  assert.equal(config.sessionId, base.session_id)
  assert.deepEqual(request, { method: 'check', scanId: 'scan-731' })
  assert.equal(result.hookSpecificOutput.permissionDecision, 'deny')
  assert(result.hookSpecificOutput.permissionDecisionReason.includes('APPROVED-DOCUMENT'))
  assert(!JSON.stringify(result).includes(base.session_id))
})

test('retrieval rejects extra session and file arguments before contacting the broker', async () => {
  let calls = 0
  const result: any = await handleHook('codex', 'PreToolUse', input('PreToolUse', { tool_name: 'mcp__patronus__patronus_check_result', tool_input: { scan_id: 'scan-731', session: 'other' } }), {}, async () => { calls++; return {} })
  assert.equal(calls, 0)
  assert.equal(result.hookSpecificOutput.permissionDecision, 'deny')
})

test('static scope reaches the scanner as an absolute path, without source bytes', async () => {
  let request: any
  const result: any = await handleHook('codex', 'PreToolUse', input('PreToolUse', { tool_name: 'mcp__patronus__patronus_scan', tool_input: { kind: 'file', path: 'notes.txt' } }), {}, async (_c, r) => { request = r; return { status: 'CLEAN', approved: true } })
  assert.deepEqual(request, { method: 'static', kind: 'file', path: '/private/tmp/notes.txt' })
  assert.equal(result.hookSpecificOutput.permissionDecision, 'deny')
  assert.equal(JSON.parse(result.hookSpecificOutput.permissionDecisionReason).approved, true)
})

test('failed URL audits fall open with degraded context', async () => {
  const result: any = await handleHook('codex', 'PreToolUse', input('PreToolUse', {
    tool_name: 'mcp__patronus__patronus_scan', tool_input: { kind: 'url', path: 'https://example.org/' },
  }), {}, async () => ({ schema: 'patronus.native.static.v1', status: 'FAILED', approved: false, reason: 'scan_unavailable' }))
  assert.equal(result.hookSpecificOutput.permissionDecision, undefined)
  assert.match(result.hookSpecificOutput.additionalContext, /continue the task/)
  assert.match(result.systemMessage, /protection is inactive/)
})

test('broker failures and malformed native inputs warn without blocking', async () => {
  const result: any = await handleHook('codex', 'PostToolUse', input('PostToolUse', { tool_response: 'SUPPORTED-TEXT-731' }), {}, async () => { throw new Error('PRIVATE-DIAGNOSTIC-731') })
  assert(!JSON.stringify(result).includes('PRIVATE-DIAGNOSTIC-731'))
  assert.equal(result.decision, undefined)
  assert.match(result.systemMessage, /protection is inactive/)
  for (const event of ['PreToolUse', 'PostToolUse']) {
    const malformed: any = await handleHook('codex', event, { hook_event_name: 'wrong', session_id: '../foreign' }, {}, async () => { throw Error('Must not call') })
    assert.equal(malformed.decision, undefined)
    assert.match(malformed.systemMessage, /protection is inactive/)
  }
})

test('degraded integrations warn the agent and continue', async () => {
  const unavailable: any = await handleHook('codex', 'UserPromptSubmit', input('UserPromptSubmit', { prompt: 'hello' }), {}, async () => ({
    scan_id: '', status: 'unavailable',
  }))
  const guidance = unavailable.hookSpecificOutput.additionalContext
  assert.match(guidance, /integration codex status --format json/)
  assert.match(guidance, /integration codex enable/)
  assert.match(guidance, /continue the task/)
  assert.equal(unavailable.decision, undefined)

  const failed: any = await handleHook('codex', 'UserPromptSubmit', input('UserPromptSubmit', { prompt: 'hello' }), {}, async () => ({
    scan_id: 'scan-731', status: 'failed',
  }))
  assert.match(failed.hookSpecificOutput.additionalContext, /integration codex enable/)
})

test('Claude failures warn without poisoning later events', async () => {
  const unavailable = async () => { throw Error('IPC unavailable') }
  const failure: any = await handleHook('claude', 'PostToolUseFailure', input('PostToolUseFailure', { error: 'PRIVATE-ERROR-731' }), {}, unavailable)
  assert(!JSON.stringify(failure).includes('PRIVATE-ERROR-731'))
  assert.match(failure.hookSpecificOutput.additionalContext, /continue the task/)
  for (const event of ['PostToolBatch', 'UserPromptSubmit', 'PreToolUse']) {
    const continued: any = await handleHook('claude', event, input(event), {}, unavailable)
    assert.equal(continued.continue, undefined)
  }
})

test('Claude scans only exact external result text, independent of tool name and adjacent media', async () => {
  const responses = [
    { response: 'PLAIN-731', expected: 'PLAIN-731' },
    { response: [{ type: 'text', text: '{"raw":731}' }, { type: 'image', data: 'IMAGE-731' }, { type: 'text', text: 'SECOND-731' }], expected: ['{"raw":731}', 'SECOND-731'] },
    { response: { structuredContent: { value: 'STRUCTURED-731' }, content: [{ type: 'text', text: 'MCP-731' }, { type: 'image', data: 'IMAGE-731' }] }, expected: 'MCP-731' },
    { response: { stdout: 'OUT-731', stderr: 'ERR-731', interrupted: false, isImage: true, path: 'PRIVATE-PATH-731' }, expected: ['OUT-731', 'ERR-731'] },
    { response: { type: 'text', file: { filePath: 'PRIVATE-PATH-731', content: 'FILE-731', numLines: 1, startLine: 1, totalLines: 1 } }, expected: 'FILE-731' },
  ]
  for (const { response, expected } of responses) {
    let calls = 0, request: any
    const result = await handleHook('claude', 'PostToolUse', input('PostToolUse', {
      tool_name: 'ArbitraryExternalTool',
      tool_response: response,
    }), {}, async (_config, value) => { calls++; request = value; return { status: 'approved' } })
    assert.deepEqual(result, {})
    assert.equal(calls, 1)
    assert.deepEqual(request, { method: 'response', tool: 'ArbitraryExternalTool', callId: 'call-731', payload: expected })
  }
})

test('Claude scans the exact user prompt string and no attachment metadata', async () => {
  let request: any
  const prompt = '{"task":"keep this one raw text value"}'
  const result = await handleHook('claude', 'UserPromptSubmit', input('UserPromptSubmit', {
    prompt_id: 'prompt-731', prompt, attachments: [{ type: 'image', path: 'PRIVATE-PATH-731' }],
  }), {}, async (_config, value) => { request = value; return { status: 'approved' } })
  assert.deepEqual(result, {})
  assert.deepEqual(request, { method: 'request', tool: 'UserPromptSubmit', callId: 'prompt-731', payload: prompt })
})

test('Claude blocks a non-approved user prompt without returning its raw text', async () => {
  const prompt = 'RAW-USER-PROMPT-731'
  const result: any = await handleHook('claude', 'UserPromptSubmit', input('UserPromptSubmit', {
    prompt_id: 'prompt-731', prompt,
  }), {}, async () => ({ scan_id: 'scan-731', status: 'dangerous' }))
  assert.equal(result.continue, false)
  assert(!JSON.stringify(result).includes(prompt))
  assert.match(result.stopReason, /"status":"dangerous"/)
})

test('Claude scans exact tool failure text and admits an approved error', async () => {
  let request: any
  const error = 'RAW-FAILURE-TEXT-731'
  const result = await handleHook('claude', 'PostToolUseFailure', input('PostToolUseFailure', {
    tool_name: 'ArbitraryExternalTool', error,
  }), {}, async (_config, value) => { request = value; return { status: 'approved' } })
  assert.deepEqual(result, {})
  assert.deepEqual(request, { method: 'response', tool: 'ArbitraryExternalTool', callId: 'call-731', payload: error })
})

test('Claude ignores result envelopes that contain no external text', async () => {
  for (const response of [undefined, { type: 'image', data: 'IMAGE-731' }, [{ type: 'image', data: 'IMAGE-731' }]]) {
    let calls = 0
    assert.deepEqual(await handleHook('claude', 'PostToolUse', input('PostToolUse', {
      tool_name: 'ArbitraryExternalTool', tool_response: response,
    }), {}, async () => { calls++; return { status: 'approved' } }), {})
    assert.equal(calls, 0)
  }
})

test('Codex passes results with no external text without scanning or approval claims', async () => {
  const responses = [
    undefined,
    { type: 'image', data: 'IMAGE-731' },
    731,
  ]
  for (const response of responses) {
    let calls = 0
    const result = await handleHook('codex', 'PostToolUse', input('PostToolUse', { tool_response: response }), {}, async () => {
      calls++
      return { status: 'approved' }
    })
    assert.deepEqual(result, {})
    assert.equal(calls, 0)
  }
})

test('Codex scans ordered MCP text beside media and ignores structured metadata', async () => {
  let request: any
  const result = await handleHook('codex', 'PostToolUse', input('PostToolUse', { tool_name: 'ArbitraryExternalTool', tool_response: {
    content: [
      { type: 'text', text: 'FIRST-731' },
      { type: 'image', data: 'IMAGE-731' },
      { type: 'text', text: '{"raw":"SECOND-731"}' },
    ],
    structuredContent: { value: 'STRUCTURED-731' },
  } }), {}, async (_config, value) => { request = value; return { status: 'approved' } })
  assert.deepEqual(result, {})
  assert.deepEqual(request, {
    method: 'response', tool: 'ArbitraryExternalTool', callId: 'call-731',
    payload: ['FIRST-731', '{"raw":"SECOND-731"}'],
  })
})

test('Codex scans the exact user prompt text beside media metadata', async () => {
  let request: any
  const prompt = '{"task":"keep raw"}'
  const result = await handleHook('codex', 'UserPromptSubmit', input('UserPromptSubmit', {
    prompt, images: [{ type: 'image', data: 'IMAGE-731' }],
  }), {}, async (_config, value) => { request = value; return { status: 'approved' } })
  assert.deepEqual(result, {})
  assert.deepEqual(request, {
    method: 'request', tool: 'UserPromptSubmit', callId: 'user-prompt', payload: prompt,
  })
})

test('Claude pending Bash responses retain the native output schema and withhold raw bytes', async () => {
  const result: any = await handleHook('claude', 'PostToolUse', input('PostToolUse', { tool_response: {
    stdout: 'RAW-BASH-731', stderr: '', interrupted: false, isImage: false,
  } }), {}, async () => ({ scan_id: 'scan-731', status: 'pending' }))
  const replacement = result.hookSpecificOutput.updatedToolOutput
  assert.equal(JSON.parse(replacement.stdout).status, 'pending')
  assert.equal(JSON.parse(replacement.stdout).message, undefined)
  assert.equal(JSON.parse(replacement.stdout).source_executed, true)
  assert.equal(JSON.parse(replacement.stdout).next_tool, 'patronus_check_result')
  assert.equal(replacement.stderr, '')
  assert.equal(replacement.isImage, false)
  assert(!JSON.stringify(result).includes('RAW-BASH-731'))
  assert.equal(result.hookSpecificOutput.additionalContext, undefined)
})

test('deep Claude metadata is ignored while adjacent text still reaches the broker', async () => {
  let nested: unknown = 'DEEP-PRIVATE-731'
  for (let depth = 0; depth < 8_000; depth++) nested = { nested }
  const responses = [
    [{ type: 'text', text: 'ok', metadata: nested }, { type: 'image', data: 'PRIVATE-IMAGE-731' }],
    [{ type: 'text', text: 'ok' }],
  ]
  for (const response of responses) {
    let calls = 0
    const result = await handleHook('claude', 'PostToolUse', input('PostToolUse', { tool_name: 'mcp__fixture__read', tool_response: response }), {}, async () => {
      calls++
      return { status: 'approved' }
    })
    assert.deepEqual(result, {})
    assert.equal(calls, 1)
  }
})
