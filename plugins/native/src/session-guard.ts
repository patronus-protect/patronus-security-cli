import { createHash, randomUUID } from 'node:crypto'
import { constants } from 'node:fs'
import { open, readFile, readdir, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { brokerFailure, prepareBroker, type BrokerConfig } from './broker.ts'

const prefix = 'pending-result-'
const marker = (directory: string, callId: string) => join(directory, prefix + createHash('sha256').update(callId).digest('hex'))

/** Record an executed call before the source result can exist. Separate marker
 * files make concurrent hook updates atomic without a shared read/modify/write. */
export async function armResult(config: BrokerConfig, callId: string): Promise<string> {
  const { directory } = await prepareBroker(config)
  const path = marker(directory, callId)
  const owner = randomUUID()
  try {
    const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
    try { await file.writeFile(owner); await file.sync() } finally { await file.close() }
  } catch (error) {
    throw brokerFailure()
  }
  return owner
}

export async function completeResult(config: BrokerConfig, callId: string, owner: string): Promise<void> {
  const { directory } = await prepareBroker(config)
  const path = marker(directory, callId)
  try {
    if (!/^[a-f0-9-]{36}$/.test(owner) || await readFile(path, 'utf8') !== owner) throw brokerFailure()
    await unlink(path)
  } catch { throw brokerFailure() }
}

export async function hasPendingResult(config: BrokerConfig): Promise<boolean> {
  try {
    const { directory } = await prepareBroker(config)
    const names = await readdir(directory)
    return names.some(name => name.startsWith(prefix))
  } catch { return true }
}
