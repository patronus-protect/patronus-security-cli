import { createHash } from 'node:crypto'
import { TOOL_ABORTED, TOOL_ABORTED_BEFORE_DISPATCH, type PostToolDecision, type ToolExecution, type ToolExecutionResult } from '@deepseek-ai/dsh-tools'

/** Reconstruct the public post-hook transformation for scanning and final verification. */
export function projectResult(result: Readonly<ToolExecutionResult>, decision: PostToolDecision): ToolExecutionResult {
  const contexts = decision.additionalContexts ?? []
  if (decision.kind === 'block') {
    const message = decision.feedback.map(block => block.type === 'text' ? block.text : `[${block.type} content]`).join('\n') || 'tool result blocked by post-execute policy'
    return { isError: true, content: decision.feedback, error: { message }, ...(contexts.length ? { additionalContexts: contexts } : {}) }
  }
  // Native output.render executes after a canonical value replacement. This path needs a host gate after rendering.
  if (Object.hasOwn(decision, 'value')) throw new Error('Patronus does not support post-hook canonical value replacement.')
  const additionalContexts = [...result.additionalContexts ?? [], ...contexts]
  return {
    ...result,
    ...(decision.content !== undefined ? { content: decision.content } : {}),
    ...(additionalContexts.length ? { additionalContexts } : {}),
  }
}

export function fingerprint(result: Readonly<ToolExecutionResult>): string {
  // Select a fixed field order, independent of lossless JSON materialization ordering.
  return createHash('sha256').update(JSON.stringify([
    result.isError, result.content, result.value, result.error, result.meta,
    result.additionalContexts, result.concludesTurn,
  ])).digest('hex')
}

/** Only the exact native cancellation projection is safe without a post-hook receipt. */
export function isNativeCancellation(exec: Readonly<ToolExecution>, result: Readonly<ToolExecutionResult>): boolean {
  if (!exec.signal.aborted || !result.isError) return false
  const messages: Record<string, string> = {
    [TOOL_ABORTED]: 'tool call aborted',
    [TOOL_ABORTED_BEFORE_DISPATCH]: 'tool call aborted before dispatch',
  }
  const message = messages[result.error.info?.code ?? '']
  return message !== undefined && fingerprint(result) === fingerprint({
    isError: true, error: { message, info: { name: 'AbortError', code: result.error.info!.code } },
    content: [{ type: 'text', text: `Error: ${message}` }],
  })
}
