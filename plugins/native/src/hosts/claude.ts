import type { HookDecision, HookInput, JsonValue } from '../types.ts'
import type { TextPayload } from '../../../deepseek/src/protocol.ts'

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function securityContext(text: string): string | undefined {
  try {
    const receipt = JSON.parse(text)
    if (!record(receipt) || typeof receipt.status !== 'string') return undefined
    if (receipt.status === 'unavailable') {
      return 'Patronus is the installed local security controller for this session. The preceding receipt reports that its scanner is unavailable. Its status and repair commands diagnose the local integration; its disable and uninstall commands explicitly turn the integration off.'
    }
    if (receipt.status === 'pending' && receipt.wait_reason === 'scanner_queue' && typeof receipt.message === 'string') {
      return receipt.message
    }
  } catch { /* Non-receipt decisions need no agent instruction. */ }
}

function visibleToolResult(text: string): string {
  try {
    const receipt = JSON.parse(text)
    if (record(receipt) && receipt.status === 'pending') {
      const { message: _message, ...metadata } = receipt
      return JSON.stringify({ ...metadata, source_executed: true, next_tool: 'patronus_check_result' })
    }
  } catch { /* Preserve non-receipt decisions verbatim. */ }
  return text
}

function textBlocks(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.flatMap(block =>
    record(block) && block.type === 'text' && typeof block.text === 'string' && block.text.length > 0 ? [block.text] : [],
  )
}

/** Raw external text exposed by the pinned Claude hook contract. */
export function claudeExternalText(event: string, input: HookInput): string[] {
  if (event === 'UserPromptSubmit') {
    if (typeof input.prompt === 'string') return input.prompt.length > 0 ? [input.prompt] : []
    if (Array.isArray(input.prompt)) return textBlocks(input.prompt)
    return record(input.prompt) ? textBlocks(input.prompt.content) : []
  }
  if (event === 'PostToolUseFailure') return typeof input.error === 'string' && input.error.length > 0 ? [input.error] : []
  if (event !== 'PostToolUse') return []
  const response = input.tool_response
  if (typeof response === 'string') return response.length > 0 ? [response] : []
  if (Array.isArray(response)) return textBlocks(response)
  if (!record(response)) return []
  if (Array.isArray(response.content)) return textBlocks(response.content)
  if (typeof response.stdout === 'string' || typeof response.stderr === 'string') {
    return [response.stdout, response.stderr].filter((value): value is string => typeof value === 'string' && value.length > 0)
  }
  if (response.type === 'text' && typeof response.text === 'string') return response.text.length > 0 ? [response.text] : []
  const file = response.type === 'text' ? response.file : undefined
  return record(file) && typeof file.content === 'string' && file.content.length > 0 ? [file.content] : []
}

export function claudeExternalTextPayload(event: string, input: HookInput): TextPayload | undefined {
  const text = claudeExternalText(event, input)
  if (text.length === 0) return undefined
  return text.length === 1 ? text[0] : text
}

export function supportsClaudeResponse(input: HookInput): boolean {
  return claudeExternalText('PostToolUse', input).length > 0
}

function replaceBlocks(value: unknown, text: string): unknown[] {
  if (!Array.isArray(value)) return []
  let replaced = false
  return value.flatMap(block => {
    if (!record(block) || block.type !== 'text' || typeof block.text !== 'string') return [block]
    if (replaced) return []
    replaced = true
    return [{ type: 'text', text }]
  })
}

function replaceClaudeResponse(response: unknown, text: string): unknown {
  if (typeof response === 'string') return text
  if (Array.isArray(response)) return replaceBlocks(response, text)
  if (!record(response)) return undefined
  if (Array.isArray(response.content)) return { ...response, content: replaceBlocks(response.content, text) }
  if (typeof response.stdout === 'string' || typeof response.stderr === 'string') {
    return { stdout: text, stderr: '', interrupted: response.interrupted === true, isImage: response.isImage === true }
  }
  if (response.type === 'text' && typeof response.text === 'string') return { type: 'text', text }
  const file = response.type === 'text' ? response.file : undefined
  if (record(file) && typeof file.content === 'string') {
    const lines = text.split('\n').length
    return { type: 'text', file: { filePath: '[Patronus]', content: text, numLines: lines, startLine: 1, totalLines: lines } }
  }
}

export function mapClaude(event: string, decision: HookDecision, input?: HookInput): object {
  if (decision.kind === 'warn') return { hookSpecificOutput: {
    hookEventName: event, additionalContext: decision.text,
  } }
  if (event === 'PreToolUse') {
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: decision.text,
      },
      ...(decision.kind === 'stop' ? { continue: false, stopReason: decision.text } : {}),
    }
  }
  if (event === 'PostToolUse' && decision.kind !== 'stop' && input && supportsClaudeResponse(input)) {
    const visible = visibleToolResult(decision.text)
    const updatedToolOutput = replaceClaudeResponse(input.tool_response, visible)
    const additionalContext = securityContext(decision.text)
    return { hookSpecificOutput: {
      hookEventName: 'PostToolUse', updatedToolOutput,
      ...(additionalContext ? { additionalContext } : {}),
    } }
  }
  return { continue: false, stopReason: decision.text }
}
