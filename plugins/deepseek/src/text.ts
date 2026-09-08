import type { ContentBlock, Message } from '@deepseek-ai/dsh-llm'
import type { ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import type { TextPayload } from './protocol.ts'

function contentText(blocks: readonly ContentBlock[]): string[] {
  const text: string[] = []
  for (const block of blocks) {
    if (block.type === 'text') text.push(block.text)
    else if (block.type === 'tool-result') text.push(...contentText(block.content))
  }
  return text
}

function record(value: JsonValue): value is { [key: string]: JsonValue } {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Raw MCP `content[].text`, when the canonical value has the MCP result shape. */
export function mcpResultText(value: JsonValue | undefined): string[] | undefined {
  if (value === undefined || !record(value) || !Array.isArray(value.content)) return undefined
  if (!value.content.every(block => record(block) && typeof block.type === 'string')) return undefined
  return value.content.flatMap(block => record(block) && block.type === 'text' && typeof block.text === 'string' ? [block.text] : [])
}

/** User-authored text blocks in host message order. */
export function userPromptText(messages: readonly Message[]): string[] {
  return messages.flatMap(message => message.source.kind === 'user' ? contentText(message.content) : [])
}

/** External tool-result text in model-visible order, independent of tool name or media siblings. */
export function toolResultText(result: Readonly<ToolExecutionResult>): string[] {
  const rawMcp = mcpResultText(result.value)
  const direct = contentText(result.content)
  // Identical projections need one scan; otherwise both external surfaces must
  // be covered. Preserve repeated blocks and ordering within each surface.
  const same = rawMcp?.length === direct.length && rawMcp.every((text, index) => text === direct[index])
  const contexts = result.additionalContexts?.flatMap(message => contentText(message.content)) ?? []
  return [...(same ? [] : rawMcp ?? []), ...direct, ...contexts]
}

export function textPayload(text: readonly string[]): TextPayload {
  return text.length === 1 ? text[0]! : [...text]
}
