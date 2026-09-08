import { chatCommand, controlChat } from '../../deepseek/src/chat-control.ts'
import { readPluginSettings, hookEnabled, type PluginSettings } from '../../deepseek/src/settings.ts'
import { isAbsolute, resolve } from 'node:path'
import { receipt } from '../../deepseek/src/receipts.ts'
import type { ScanResult } from '../../deepseek/src/protocol.ts'
import { invalidScanReference } from '../../deepseek/src/references.ts'
import { callBroker, isSessionQuarantined, quarantineSession, type BrokerConfig } from './broker.ts'
import { codexExternalTextPayload, mapCodex } from './hosts/codex.ts'
import { claudeExternalTextPayload, mapClaude } from './hosts/claude.ts'
import { armResult, hasPendingResult } from './session-guard.ts'
import { recordProtocolScan, type ProtocolRecorder } from './protocol.ts'
import type { HookDecision, HookInput, Host, JsonValue } from './types.ts'

const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value)
const failed = JSON.stringify(receipt({ scan_id: '', status: 'failed' }))
const quarantine = 'Patronus stopped this session because an unsupported tool result may be present in its history. Start a new session after correcting the integration.'
const id = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,256}$/.test(value)
const ownPrefixes: Record<Host, string[]> = {
  codex: ['mcp__patronus__'],
  claude: ['mcp__patronus__', 'mcp__plugin_patronus-security_patronus__'],
}
const operations = new Map([['patronus_check_result', 'check'], ['patronus_read_redacted', 'read_redacted'], ['patronus_scan', 'static']])

function inactiveMessage(host: Host): string {
  const base = `patronus-security-scanner integration ${host}`
  return `Patronus is not active for ${host}, so no security approval was granted. Check: ${base} status --format json. Repair: ${base} enable. To continue without Patronus, run ${base} disable or ${base} uninstall, then start a new session.`
}

function visibleResult(result: ScanResult, host: Host, direction: 'request' | 'response' = 'response'): JsonValue {
  const value = receipt(result, direction)
  if (result.status === 'unavailable' && record(value)) value.message = inactiveMessage(host)
  return value
}

function ownOperation(host: Host, name: string): string | undefined {
  for (const prefix of ownPrefixes[host]) if (name.startsWith(prefix)) return operations.get(name.slice(prefix.length))
}

type Overrides = Pick<BrokerConfig, 'stateDir' | 'executable' | 'configPath' | 'responseWaitMs' | 'requestTimeoutMs'>
const sessionSafety = { isQuarantined: isSessionQuarantined, quarantine: quarantineSession, arm: armResult, hasPending: hasPendingResult }
type SessionSafety = {
  isQuarantined(config: BrokerConfig): Promise<boolean>
  quarantine(config: BrokerConfig): Promise<void>
  arm(config: BrokerConfig, callId: string): Promise<string | void>
  hasPending(config: BrokerConfig): Promise<boolean>
}

/** Hooks supply session attribution. Model arguments never carry a capability. */
export async function handleHook(host: Host, event: string, value: unknown, overrides: Overrides = {}, rpc: typeof callBroker = callBroker, safety: SessionSafety = sessionSafety, armed: (owner: string) => void = () => {}, protocol: ProtocolRecorder = recordProtocolScan, settings: () => PluginSettings = readPluginSettings, control: typeof controlChat = controlChat): Promise<object> {
  const map = (decision: HookDecision) => host === 'codex' ? mapCodex(event, decision) : mapClaude(event, decision, value as HookInput)
  const deny = (text = failed) => map({ kind: event === 'PreToolUse' ? 'deny' : 'replace', text })
  let config: BrokerConfig | undefined
  try {
    if (!record(value) || value.hook_event_name !== event || !id(value.session_id) ||
        typeof value.cwd !== 'string' || !isAbsolute(value.cwd)) return deny()
    const input = value as unknown as HookInput
    config = { ...overrides, host, sessionId: input.session_id, cwd: input.cwd }
    const scan = (request: Parameters<typeof rpc>[1]) => protocol(config!, request, () => rpc(config!, request))
    if (event === 'SessionEnd' || event === 'Stop') { await scan({ method: 'close' }); return {} }
    if (event === 'UserPromptSubmit') {
      const payload = host === 'codex' ? codexExternalTextPayload(event, input) : claudeExternalTextPayload(event, input)
      const action = chatCommand(payload)
      if (action) return map({ kind: 'replace', text: await control(host, input.session_id, action, config.executable) })
    }
    const policy = settings()
    // Explicit chat/global pause bypasses the gate; durable quarantine is retained for resume.
    if ((!policy.enabled || policy.disabled_chats[host].includes(input.session_id)) && !(event === 'PreToolUse' && typeof input.tool_name === 'string' && ownOperation(host, input.tool_name))) return {}
    const enabled = (surface: 'user_input' | 'tool_result' | 'mcp_result') => hookEnabled(policy, host, input.session_id, surface)
    const responseEnabled = () => enabled(input.tool_name?.startsWith('mcp__') ? 'mcp_result' : 'tool_result')
    if (await safety.isQuarantined(config)) return map({ kind: 'stop', text: quarantine })
    if (event === 'PostToolUseFailure') {
      if (!responseEnabled()) return {}
      if (host !== 'claude') {
        await safety.arm(config, id(input.tool_use_id) ? input.tool_use_id : 'invalid-failure')
        await safety.quarantine(config)
        return map({ kind: 'stop', text: quarantine })
      }
      if (!id(input.tool_use_id) || typeof input.tool_name !== 'string' || !input.tool_name || input.tool_name.length > 256) throw Error('Invalid tool metadata.')
      const payload = claudeExternalTextPayload(event, input)
      if (payload === undefined) return {}
      const owner = await safety.arm(config, input.tool_use_id)
      if (owner) armed(owner)
      const result = await scan({ method: 'response', tool: input.tool_name, callId: input.tool_use_id, payload }) as unknown as ScanResult
      if (result.status === 'approved') return {}
      await safety.quarantine(config)
      return map({ kind: 'stop', text: JSON.stringify(visibleResult(result, host)) })
    }
    if (!['PreToolUse', 'PostToolUse'].includes(event) && await safety.hasPending(config)) {
      await safety.quarantine(config)
      return map({ kind: 'stop', text: quarantine })
    }
    if (event === 'UserPromptSubmit') {
      if (!enabled('user_input')) return {}
      const payload = host === 'codex' ? codexExternalTextPayload(event, input) : claudeExternalTextPayload(event, input)
      if (payload === undefined) return {}
      const callId = id(input.prompt_id) ? input.prompt_id : 'user-prompt'
      const result = await scan({ method: 'request', tool: 'UserPromptSubmit', callId, payload }) as unknown as ScanResult
      return result.status === 'approved' ? {} : map({ kind: 'replace', text: JSON.stringify(visibleResult(result, host, 'request')) })
    }
    if (!['PreToolUse', 'PostToolUse'].includes(event)) return {}
    if (!id(input.tool_use_id) || typeof input.tool_name !== 'string' || !input.tool_name || input.tool_name.length > 256) throw Error('Invalid tool metadata.')
    const operation = ownOperation(host, input.tool_name)
    if (event === 'PreToolUse' && operation) {
      const args = input.tool_input
      if (!record(args)) return deny()
      let result: JsonValue
      if (operation === 'static') {
        if (Object.keys(args).some(key => !['kind', 'path', 'server'].includes(key)) || typeof args.kind !== 'string' ||
            !['repo', 'directory', 'file', 'url', 'mcp'].includes(args.kind) || typeof args.path !== 'string' || !args.path || args.path.includes('\0')) return deny()
        if (args.server !== undefined && (args.kind !== 'mcp' || typeof args.server !== 'string' || !args.server || args.server.length > 256)) return deny()
        const target = args.kind === 'url' || args.kind === 'mcp' && args.path.startsWith('https://') ? args.path : resolve(input.cwd, args.path)
        result = await scan({ method: 'static', kind: args.kind as 'repo' | 'directory' | 'file' | 'url' | 'mcp', path: target, ...(args.server === undefined ? {} : {server: args.server as string}) })
      } else {
        if (Object.keys(args).some(key => key !== 'scan_id') || !id(args.scan_id)) return deny()
        const invalid = invalidScanReference(args.scan_id)
        if (invalid) return deny(JSON.stringify(invalid))
        result = await scan({ method: operation as 'check' | 'read_redacted', scanId: args.scan_id })
      }
      // Return a safe result as deny feedback; the placeholder never executes and
      // no hidden session token is inserted into model-visible tool arguments.
      const visible = record(result) && result.status === 'unavailable'
        ? { ...result, message: inactiveMessage(host) }
        : result
      return map({ kind: 'deny', text: JSON.stringify(visible) })
    }
    if (event === 'PreToolUse') {
      return {}
    }
    if (!responseEnabled()) return {}
    const payload = host === 'codex' ? codexExternalTextPayload(event, input) : claudeExternalTextPayload(event, input)
    if (payload === undefined) return {}
    const owner = await safety.arm(config, input.tool_use_id)
    if (owner) armed(owner)
    const result = await scan({ method: 'response', tool: input.tool_name, callId: input.tool_use_id, payload }) as unknown as ScanResult
    return result.status === 'approved' ? {} : map({ kind: 'replace', text: JSON.stringify(visibleResult(result, host)) })
  } catch {
    if (host === 'claude' && ['PostToolUse', 'PostToolUseFailure'].includes(event)) {
      if (config) try { await safety.quarantine(config) } catch { /* Future safety checks fail closed if private state is unavailable. */ }
      return map({ kind: 'stop', text: quarantine })
    }
    return deny()
  }
}
