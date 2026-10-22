import { createHash, randomBytes } from 'node:crypto'
import { closeSync, constants, fstatSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { patronusRoot } from '../../deepseek/src/settings.ts'
import type { Host } from './types.ts'

/**
 * User confirmation for a medium-risk shell command on hosts whose hooks cannot open an approval
 * dialog (Codex rejects PreToolUse `ask`). The hook denies the command and issues a one-time token;
 * only the user's own next message can carry it (UserPromptSubmit), which approves exactly that
 * command once. A model-written token in a tool call never reaches this path.
 */
const token = /\bpatronus_allow ([a-f0-9]{32})\b/g
const PENDING_MS = 15 * 60_000
const APPROVED_MS = 5 * 60_000
type State = { nonce: string; digest: string; expires: number; approved: boolean }

const digest = (command: string) => createHash('sha256').update(command.trim()).digest('hex')
const pathFor = (host: Host, chat: string) => join(patronusRoot(), 'command-approval', createHash('sha256').update(`${host}:${chat}`).digest('hex'))

function write(file: string, state: State): void {
  mkdirSync(join(patronusRoot(), 'command-approval'), { recursive: true, mode: 0o700 })
  const temp = `${file}.${randomBytes(8).toString('hex')}`
  const fd = openSync(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600)
  try { writeFileSync(fd, JSON.stringify(state)) } finally { closeSync(fd) }
  renameSync(temp, file)
}

/** Claims the state file so concurrent hooks cannot both use one approval. */
function claim(file: string): State | undefined {
  const claimed = `${file}.${randomBytes(8).toString('hex')}`
  try { renameSync(file, claimed) } catch { return undefined }
  try {
    const fd = openSync(claimed, constants.O_RDONLY | constants.O_NOFOLLOW)
    try {
      const stat = fstatSync(fd)
      if (!stat.isFile() || stat.size > 1024 || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()) return undefined
      return JSON.parse(readFileSync(fd, 'utf8')) as State
    } finally { closeSync(fd) }
  } catch { return undefined } finally { rmSync(claimed, { force: true }) }
}

/** Issues the token for one command in one chat; a newer request replaces an older one. */
export function requestCommandApproval(host: Host, chat: string, command: string): string | undefined {
  try {
    const nonce = randomBytes(16).toString('hex')
    write(pathFor(host, chat), { nonce, digest: digest(command), expires: Date.now() + PENDING_MS, approved: false })
    return `patronus_allow ${nonce}`
  } catch { return undefined }
}

/** Called with the user's own prompt text. Returns true when it approved a pending command. */
export function approveFromPrompt(host: Host, chat: string, prompt: string): boolean {
  const matches = [...prompt.matchAll(token)]
  if (matches.length !== 1) return false
  const file = pathFor(host, chat)
  const state = claim(file)
  if (!state) return false
  if (state.approved || state.expires <= Date.now() || state.nonce !== matches[0]![1]) {
    if (state.expires > Date.now()) try { write(file, state) } catch { /* The token stays unusable. */ }
    return false
  }
  try { write(file, { ...state, approved: true, expires: Date.now() + APPROVED_MS }); return true } catch { return false }
}

/** True exactly once for the approved command; anything else leaves the state untouched. */
export function consumeCommandApproval(host: Host, chat: string, command: string): boolean {
  const file = pathFor(host, chat)
  const state = claim(file)
  if (!state) return false
  if (state.approved && state.expires > Date.now() && state.digest === digest(command)) return true
  if (state.expires > Date.now()) try { write(file, state) } catch { /* Expired by failure. */ }
  return false
}
