import assert from 'node:assert/strict'
import test from 'node:test'
import { chmod, mkdtemp, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { prepareBroker, type BrokerConfig } from '../src/broker.ts'
import { armResult, completeResult, hasPendingResult } from '../src/session-guard.ts'

async function fixture(): Promise<{ config: BrokerConfig; roots: string[] }> {
  const cwd = await mkdtemp(join(tmpdir(), 'patronus-guard-cwd-'))
  const stateDir = await mkdtemp(join(tmpdir(), 'patronus-guard-state-'))
  return { config: { host: 'claude', sessionId: 'guard-session-731', cwd, stateDir }, roots: [cwd, stateDir] }
}

test('pending-result guard is durable and rejects duplicate call identities', async () => {
  const { config, roots } = await fixture()
  try {
    assert.equal(await hasPendingResult(config), false)
    const owner = await armResult(config, 'call-731')
    assert.equal(await hasPendingResult(config), true)
    await assert.rejects(armResult(config, 'call-731'), /broker unavailable/)
    await assert.rejects(completeResult(config, 'call-731', crypto.randomUUID()), /broker unavailable/)
    assert.equal(await hasPendingResult(config), true)
    await completeResult(config, 'call-731', owner)
    assert.equal(await hasPendingResult(config), false)
  } finally { for (const root of roots) await rm(root, { recursive: true, force: true }) }
})

test('pending-result guard fails closed for forged markers and permissive state', async () => {
  const first = await fixture()
  try {
    const prepared = await prepareBroker(first.config)
    const target = join(prepared.directory, 'pending-result-' + '0'.repeat(64))
    await symlink('/private/tmp', target)
    assert.equal(await hasPendingResult(first.config), true)
  } finally { for (const root of first.roots) await rm(root, { recursive: true, force: true }) }

  const second = await fixture()
  try {
    await chmod(second.config.stateDir!, 0o755)
    assert.equal(await hasPendingResult(second.config), true)
    await assert.rejects(armResult(second.config, 'call-731'), /broker unavailable/)
  } finally { for (const root of second.roots) await rm(root, { recursive: true, force: true }) }
})
