import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { executablePath } from './client.ts'
import { readPluginSettings, type PluginHost } from './settings.ts'

export type ChatAction = 'on' | 'off' | 'status'
const run = promisify(execFile)

/** Only an entire user-authored text value is a control, never result text or a quoted fragment. */
export function chatCommand(payload: unknown): ChatAction | undefined {
  const text = Array.isArray(payload) && payload.length === 1 ? payload[0] : payload
  if (typeof text !== 'string') return undefined
  const match = /^\/?patronus (on|off|status)$/i.exec(text.trim())
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
  const paused = !settings.enabled || settings.disabled_chats[host].includes(session)
  const enabled = Object.entries(settings.hooks).filter(([, active]) => active).map(([name]) => name)
  if (paused) return 'Patronus is OFF for this chat. Future input and results will not be scanned. Send "patronus on" to resume.'
  if (enabled.length === 0) return 'Patronus has no active hooks. Enable hooks in the shared plugin settings.'
  return `Patronus is ON for future text in this chat. Active hooks: ${enabled.join(', ')}. Earlier result history is not scanned retroactively. Send "patronus off" to pause.`
}
