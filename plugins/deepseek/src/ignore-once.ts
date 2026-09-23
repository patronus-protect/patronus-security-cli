import { createHash, randomBytes } from 'node:crypto'
import { closeSync, constants, fstatSync, linkSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { patronusRoot, type PluginHost } from './settings.ts'
import type { ScanResult, TextPayload } from './protocol.ts'

const command = /\bignore_once ([A-Za-z0-9_.:-]{1,256})_([a-f0-9]{32})\b/g
/** The command plus quoting or punctuation people add when pasting it, e.g. `...`, "...", or a final period. */
const pasted = /[`'"(\[<]*\bignore_once [A-Za-z0-9_.:-]{1,256}_[a-f0-9]{32}\b[`'")\]>.,;:!?]*/g
/** Whitespace, line endings and the command itself do not change which prompt a challenge is for. */
const normalize = (part: string) => part.replace(pasted, ' ').replace(/\s+/g, ' ').trim()
const digest = (text: readonly string[]) => createHash('sha256').update(JSON.stringify(text.map(normalize))).digest('hex')
const parts = (payload: TextPayload): string[] => typeof payload === 'string' ? [payload] : payload
const directory = () => join(patronusRoot(), 'ignore-once')
const pathFor = (host: PluginHost, chat: string) => join(directory(), createHash('sha256').update(`${host}:${chat}`).digest('hex'))

export function stripIgnoreOnce(text: string): string { return text.replace(pasted, ' ').replace(/[ \t]{2,}/g, ' ').trim() }
export function hasIgnoreOnce(text: TextPayload): boolean { return parts(text).some(part => [...part.matchAll(command)].length > 0) }

export function injectionFinding(result: ScanResult): boolean {
  return result.status === 'dangerous' && Array.isArray(result.findings) && result.findings.some(finding =>
    finding !== null && typeof finding === 'object' && !Array.isArray(finding) &&
    (finding.category === 'prompt_injection' || finding.category === 'injection'))
}

/**
 * The challenge is private state, scoped to one host, chat and prompt. A retry that
 * still carries an older command is bound to its text without that command.
 */
export function issueIgnoreOnce(host: PluginHost, chat: string, payload: TextPayload): string | undefined {
  try {
    const root = directory()
    mkdirSync(root, { recursive: true, mode: 0o700 })
    const nonce = randomBytes(16).toString('hex')
    const file = pathFor(host, chat)
    const temp = `${file}.${nonce}`
    const fd = openSync(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600)
    try { writeFileSync(fd, JSON.stringify({ nonce, digest: digest(parts(payload)), expires: Date.now() + 15 * 60_000 })) }
    finally { closeSync(fd) }
    renameSync(temp, file)
    return `ignore_once ${chat}_${nonce}`
  } catch { return undefined }
}

/**
 * Rename claims the challenge before validation, so concurrent retries cannot both pass.
 * Only a successful or expired claim ends the challenge; a mismatched retry restores it.
 */
export function consumeIgnoreOnce(host: PluginHost, chat: string, payload: TextPayload): boolean {
  try {
    const text = parts(payload)
    const matches = text.flatMap(part => [...part.matchAll(command)])
    if (matches.length !== 1 || matches[0]![1] !== chat) return false
    const nonce = matches[0]![2]!
    const file = pathFor(host, chat)
    const claimed = `${file}.${randomBytes(16).toString('hex')}`
    try { renameSync(file, claimed) } catch { return false }
    try {
      const fd = openSync(claimed, constants.O_RDONLY | constants.O_NOFOLLOW)
      let state: { nonce: string; digest: string; expires: number }
      try {
        const stat = fstatSync(fd)
        if (!stat.isFile() || stat.size > 1024 || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()) return false
        state = JSON.parse(readFileSync(fd, 'utf8'))
      } finally { closeSync(fd) }
      if (state.expires <= Date.now()) return false
      if (state.nonce === nonce && state.digest === digest(text)) return true
      // A mistyped or edited retry must not burn the challenge the user still holds.
      // link fails if a newer challenge was issued meanwhile; that one then stays authoritative.
      try { linkSync(claimed, file) } catch { /* Keep the newer challenge. */ }
      return false
    } finally { rmSync(claimed, { force: true }) }
  } catch { return false }
}
