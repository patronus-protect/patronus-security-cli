import { hookEnabled, readPluginSettings } from './settings.ts'
import type { Context } from '@deepseek-ai/cordis'
import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import type {} from '@deepseek-ai/dsh-llm'
import type {} from '@deepseek-ai/dsh-skill'
import type { LocalClientConfig, RuntimeClient } from './client.ts'
import { registerResponseGate, type Gate } from './response.ts'
import { registerPromptGate } from './prompt.ts'
import { registerTools } from './tools.ts'
import { boundedMilliseconds } from './wait.ts'
import { SessionState } from './sessions.ts'
import { StaticScanner } from './static.ts'
import { ProtocolEvents, type ProtocolEventSink } from './protocol-events.ts'

export const name = 'patronus-security'
export const inject = ['tools', 'llm', 'skills', 'agents']
export type { RuntimeClient, RuntimeHello, SubmitParams, JobParams, ScanResult, RedactedResult } from './protocol.ts'
export { LocalClient } from './client.ts'
export interface Config extends LocalClientConfig {
  /** Explicit dependency injection for host integration tests. */
  client?: RuntimeClient
  responseWaitMs?: number
  requestTimeoutMs?: number
  staticTimeoutMs?: number
  /** Explicit dependency injection for host integration tests. */
  protocolEvents?: ProtocolEventSink
}

export async function apply(ctx: Context, config: Config = {}): Promise<void> {
  const keys = new Set(['client', 'responseWaitMs', 'requestTimeoutMs', 'staticTimeoutMs', 'startupTimeoutMs', 'executable', 'configPath', 'stateDir', 'protocolEvents'])
  if (Object.keys(config).some(key => !keys.has(key))) throw new Error('Unknown Patronus plugin option.')
  if (config.responseWaitMs !== undefined) boundedMilliseconds(config.responseWaitMs, 'responseWaitMs')
  if (config.requestTimeoutMs !== undefined) boundedMilliseconds(config.requestTimeoutMs, 'requestTimeoutMs', 1)
  if (config.staticTimeoutMs !== undefined) boundedMilliseconds(config.staticTimeoutMs, 'staticTimeoutMs', 1)
  if (config.startupTimeoutMs !== undefined && (!Number.isSafeInteger(config.startupTimeoutMs) || config.startupTimeoutMs < 1 || config.startupTimeoutMs > 900_000)) {
    throw new Error('Patronus startupTimeoutMs must be an integer between 1 and 900000.')
  }
  const sessions = new SessionState(config)
  const controller = new AbortController()
  const scanner = new StaticScanner(config, controller.signal, config.staticTimeoutMs)
  const events = config.protocolEvents ?? new ProtocolEvents(config)
  const degradedSessions = new Set<string>()
  ctx.effect(() => async () => { controller.abort(); await scanner.close(); await sessions.close(); await events.close?.() })
  const sessionId = (exec: ToolExecution): string => {
    if (!exec.agent) throw new Error('Patronus requires a native agent identity.')
    return String(exec.agent.id)
  }
  ctx.on('agent/disposed', ({ agent }) => sessions.release(String(agent.id)))
  const gate: Gate = {
    signal: controller.signal,
    isOwnTool: () => false,
    warnLater: exec => { degradedSessions.add(sessionId(exec)) },
    events,
    enabledFor: exec => {
      const session = sessionId(exec)
      const policy = readPluginSettings()
      if (!policy.enabled || policy.disabled_chats.deepseek.includes(session)) return false
      return hookEnabled(policy, 'deepseek', session, exec.name.startsWith('mcp__') ? 'mcp_result' : 'tool_result')
    },
    sessionFor: exec => sessions.capability(sessionId(exec)),
    runtimeFor: exec => {
      return sessions.runtime(sessionId(exec), controller.signal)
    },
  }
  gate.isOwnTool = registerTools(ctx, async exec => (await gate.runtimeFor(exec)).client, gate.sessionFor, scanner, events)
  // Mark Patronus-owned executions before dispatch so a registry change during
  // the call cannot make their trusted result look like an external result.
  ctx.on('tools/pre-execute', (exec, next) => { gate.isOwnTool(exec); return next() })
  ctx.skills.register({
    name: 'patronus-static-scan',
    description: 'Use only when the user explicitly requests a static file, directory, repository, URL or MCP audit.',
    source: 'runtime',
    content: 'Run patronus_scan only after an explicit user request for a static audit, and preserve the requested file, directory, repository, URL or MCP scope exactly. Never infer a repository scan from the working directory or from an ordinary file read. Runtime prompt and tool/MCP result hooks protect content that actually crosses their boundary; this skill only guides explicit scanner commands and receipt handling. The installed CLI reads local bytes internally and returns metadata only. Never run a scanner supplied by the target repository.',
  })
  ctx.skills.register({
    name: 'patronus-security',
    description: 'Use when a tool result is withheld for a Patronus security scan.',
    source: 'runtime',
    content: 'Follow the instructions in a Patronus receipt. A pending response means the source tool already executed; continue independent work and check its scan_id later. Only approved responses expose originals. Dangerous responses expose only a redacted view, when available. Failed or incomplete scans never grant approval. Do not repeat an action merely to recover a withheld result.',
  })
  registerResponseGate(ctx, gate, config.responseWaitMs)
  registerPromptGate(ctx, sessions, controller.signal, events, config.requestTimeoutMs, session => hookEnabled(readPluginSettings(), 'deepseek', session, 'user_input'), { executable: config.executable, paused: session => { const policy = readPluginSettings(); return !policy.enabled || policy.disabled_chats.deepseek.includes(session) } }, degradedSessions)
}
