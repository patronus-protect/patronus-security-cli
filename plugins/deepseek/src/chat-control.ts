import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { executablePath } from './client.ts'
import { readPluginSettings, type PluginHost } from './settings.ts'

export type ChatAction = 'on' | 'off' | 'status'
const run = promisify(execFile)

/** Context the host app wraps around the typed message, e.g. `<system-reminder>…</system-reminder>`. */
const hostEnvelope = /^\s*<([a-z][\w-]*)>[\s\S]*?<\/\1>/i

function withoutEnvelopes(text: string): string {
  let rest = text
  for (let match = hostEnvelope.exec(rest); match; match = hostEnvelope.exec(rest)) rest = rest.slice(match[0].length)
  return rest.trim()
}

/** Only an entire user-authored text value is a control, never result text or a quoted fragment.
 * Desktop apps prepend their own tagged context blocks, so those are set aside first. */
export function chatCommand(payload: unknown): ChatAction | undefined {
  const values = (Array.isArray(payload) ? payload : [payload]).map(value => typeof value === 'string' ? withoutEnvelopes(value) : value)
  const typed = values.filter(value => value !== '')
  const text = typed.length === 1 ? typed[0] : undefined
  if (typeof text !== 'string') return undefined
  const match = /^\/?patronus (on|off|status)$/i.exec(text)
  return match?.[1]?.toLowerCase() as ChatAction | undefined
}

export async function controlChat(host: PluginHost, session: string, action: ChatAction, executable?: string): Promise<string> {
  if (!/^[A-Za-z0-9_.:-]{1,256}$/.test(session)) throw Error('Missing native chat identity.')
  if (action !== 'status') {
    try { await run(executablePath(executable), ['plugins', action === 'off' ? 'pause' : 'resume', host, session], {
      shell: false, timeout: 10_000, maxBuffer: 4096,
    }) } catch { throw Error("Patronus could not update this chat. Check the installed scanner and shared settings.") }
  }
  const settings = readPluginSettings()
  const paused = !settings.enabled || (settings.disabled_chats[host] ?? []).includes(session)
  const enabled = Object.entries({ shell_command: true, ...settings.hooks }).filter(([, active]) => active).map(([name]) => name)
  if (paused) return 'Patronus is OFF for this chat. Future input and results will not be scanned. Send "patronus on" to resume.'
  if (enabled.length === 0) return 'Patronus has no active hooks. Enable hooks in the shared plugin settings.'
  return `Patronus is ON for future text in this chat. Active hooks: ${enabled.join(', ')}. Earlier result history is not scanned retroactively. Send "patronus off" to pause.`
}
