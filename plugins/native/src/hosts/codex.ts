import type { HookDecision, HookInput } from '../types.ts'
import type { TextPayload } from '../../../deepseek/src/protocol.ts'

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/** Raw external text exposed by the pinned Codex hook contract. */
export function codexExternalText(event: string, input: HookInput): string[] {
  if (event === 'UserPromptSubmit') return typeof input.prompt === 'string' && input.prompt.length > 0 ? [input.prompt] : []
  if (event !== 'PostToolUse') return []
  const response = input.tool_response
  if (typeof response === 'string') return response.length > 0 ? [response] : []
  if (!record(response) || !Array.isArray(response.content)) return []
  return response.content.flatMap(block =>
    record(block) && block.type === 'text' && typeof block.text === 'string' && block.text.length > 0 ? [block.text] : [],
  )
}

export function codexExternalTextPayload(event: string, input: HookInput): TextPayload | undefined {
  const text = codexExternalText(event, input)
  if (text.length === 0) return undefined
  return text.length === 1 ? text[0] : text
}

export function mapCodex(event: string, decision: HookDecision): object {
  if (decision.kind === 'warn') return {
    systemMessage: decision.text,
    hookSpecificOutput: { hookEventName: event, additionalContext: decision.text },
  }
  if (event === 'PreToolUse') return { hookSpecificOutput: {
    hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: decision.text,
  } }
  // Unlike continue:false, block also rejects a nested code-mode tool promise.
  if (event === 'PostToolUse' || event === 'UserPromptSubmit') return { decision: 'block', reason: decision.text }
  return { continue: false, stopReason: decision.text }
}
