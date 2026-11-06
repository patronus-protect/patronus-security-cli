import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'
import type { CommandResult } from './protocol.ts'
import type { Gate } from './response.ts'

/** dsh's shell tools; both carry the command line as `arguments.command`. */
const shellTools = new Set(['bash', 'pwsh'])

export function shellCommandOf(exec: ToolExecution): string | undefined {
  const args = exec.arguments
  if (!shellTools.has(exec.name) || args === null || typeof args !== 'object' || Array.isArray(args)) return undefined
  const command = (args as Record<string, unknown>).command
  return typeof command === 'string' && command.trim() ? command : undefined
}

const score = (result: CommandResult) => typeof result.decision_score === 'number' ? `, score ${result.decision_score.toFixed(1)}` : ''

/**
 * Pre-execution shell command check. A medium-risk command goes through dsh's approval service (`ask`), so
 * the user decides; Patronus never blocks a command on its own. Low risk and an unavailable check let it run.
 */
export async function checkCommand(exec: ToolExecution, gate: Gate, enabled: (exec: ToolExecution) => boolean): Promise<PreToolDecision | undefined> {
  const command = shellCommandOf(exec)
  if (command === undefined || !enabled(exec)) return undefined
  try {
    const runtime = await gate.runtimeFor(exec)
    if (!runtime.client.checkCommand) return undefined
    const result = await runtime.client.checkCommand({ session: gate.sessionFor(exec), tool: exec.name, call_id: String(exec.callId), command }, AbortSignal.any([exec.signal, gate.signal]))
    // Low lies within the model's 0.1% FPR threshold, where routine developer work scores.
    if (result.status !== 'dangerous' || result.risk === 'low') return undefined
    return { kind: 'ask', reason: `Patronus flagged this shell command as risky (shell-command risk${score(result)}). Allow it only if you expect this command.` }
  } catch { return undefined }
}
