import { constants, closeSync, fstatSync, openSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'

export const patronusRoot = () => {
  const root = process.env.PATRONUS_DATA_DIR ?? join(homedir(), '.patronus-security-scanner')
  if (!isAbsolute(root)) throw Error('Patronus data directory must be absolute.')
  return root
}
export type Surface = 'user_input' | 'tool_result' | 'mcp_result'
export type PluginHost = 'codex' | 'claude' | 'deepseek'
export interface PluginSettings {
  schema_version: 1
  enabled: boolean
  hooks: Record<Surface, boolean>
  disabled_chats: Record<PluginHost, string[]>
}
export const defaultSettings = (): PluginSettings => ({
  schema_version: 1, enabled: true,
  hooks: { user_input: true, tool_result: true, mcp_result: true },
  disabled_chats: { codex: [], claude: [], deepseek: [] },
})
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value)

/** Trusted local settings only. Malformed or inaccessible settings fail closed. */
export function readPluginSettings(path = process.env.PATRONUS_PLUGIN_SETTINGS ?? join(patronusRoot(), 'plugins.json')): PluginSettings {
  if (!isAbsolute(path)) throw Error('Patronus settings path must be absolute.')
  let fd: number
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW) }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return defaultSettings(); throw error }
  let value: unknown
  try {
    const info = fstatSync(fd)
    if (!info.isFile() || info.size > 256 * 1024 || (process.getuid && info.uid !== process.getuid()) || (info.mode & 0o022) !== 0) throw Error('Unsafe Patronus settings file.')
    value = JSON.parse(readFileSync(fd, 'utf8'))
  } finally { closeSync(fd) }
  const defaults = defaultSettings()
  if (!object(value) || Object.keys(value).some(key => !Object.hasOwn(defaults, key)) || value.schema_version !== 1 ||
      typeof value.enabled !== 'boolean' || !object(value.hooks) || !object(value.disabled_chats)) throw Error('Invalid Patronus settings.')
  if (Object.keys(value.hooks).length !== 3 || Object.keys(defaults.hooks).some(key => typeof (value.hooks as Record<string, unknown>)[key] !== 'boolean')) throw Error('Invalid Patronus hooks.')
  if (Object.keys(value.disabled_chats).length !== 3) throw Error('Invalid Patronus chat settings.')
  for (const host of Object.keys(defaults.disabled_chats)) {
    const ids = value.disabled_chats[host]
    if (!Array.isArray(ids) || ids.length > 1000 || ids.some(id => typeof id !== 'string' || !/^[A-Za-z0-9_.:-]{1,256}$/.test(id))) throw Error('Invalid Patronus chat ID.')
  }
  return value as unknown as PluginSettings
}

export function hookEnabled(settings: PluginSettings, host: PluginHost, chat: string, surface: Surface): boolean {
  return settings.enabled && settings.hooks[surface] && !settings.disabled_chats[host].includes(chat)
}
