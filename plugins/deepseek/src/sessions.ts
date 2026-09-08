import { createHash, randomUUID } from 'node:crypto'
import { closeSync, constants, fsyncSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs'
import { patronusRoot } from './settings.ts'
import { dirname, join } from 'node:path'
import { LocalClient, type LocalClientConfig } from './client.ts'
import type { RuntimeClient, RuntimeHello } from './protocol.ts'
import { boundedMilliseconds } from './wait.ts'

export interface SessionRuntime { client: RuntimeClient; hello: RuntimeHello }
const privateFailure = () => new Error('Patronus private session state is unavailable or invalid.')

/** Native session IDs select private records; model tool arguments never select paths. */
export class SessionState {
  private readonly root: string
  private readonly clients = new Set<RuntimeClient>()
  private readonly runtimes = new Map<string, Promise<SessionRuntime>>()
  private readonly ownedClients = new Map<string, RuntimeClient>()
  private readonly releasing = new Map<string, Promise<void>>()
  private readonly capabilities = new Map<string, string>()

  constructor(private readonly config: LocalClientConfig & { client?: RuntimeClient }) {
    this.root = config.stateDir ?? join(patronusRoot(), 'deepseek-sessions')
    if (config.client) this.clients.add(config.client)
  }

  capability(id: string): string {
    if (!id) throw privateFailure()
    const cached = this.capabilities.get(id)
    if (cached) return cached
    const directory = this.directory(id)
    const path = join(directory, 'capability')
    this.createPrivateFile(path, randomUUID())
    let descriptor: number | undefined
    try {
      descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
      const stat = fstatSync(descriptor)
      if (!stat.isFile() || stat.size > 128 || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()) throw privateFailure()
      const capability = readFileSync(descriptor, 'utf8')
      if (!/^[a-f0-9-]{36}$/.test(capability)) throw privateFailure()
      this.capabilities.set(id, capability)
      return capability
    } catch { throw privateFailure() }
    finally { if (descriptor !== undefined) closeSync(descriptor) }
  }

  assertUsable(id: string | undefined): void {
    if (!id) throw new Error('Patronus requires native session attribution.')
    this.capability(id)
  }

  runtime(id: string, signal: AbortSignal): Promise<SessionRuntime> {
    this.assertUsable(id)
    const releasing = this.releasing.get(id)
    if (releasing) return releasing.then(() => this.runtime(id, signal))
    let runtime = this.runtimes.get(id)
    if (!runtime) {
      const client = this.config.client ?? new LocalClient({
        executable: this.config.executable, configPath: this.config.configPath,
        stateDir: join(this.directory(id), 'scanner'),
        startupTimeoutMs: this.config.startupTimeoutMs,
      })
      this.clients.add(client)
      if (!this.config.client) this.ownedClients.set(id, client)
      runtime = client.hello(signal).then(hello => {
        if (hello.protocol_version !== 1 || !['local', 'api', 'hybrid'].includes(hello.provider) || hello.ready !== true) throw privateFailure()
        boundedMilliseconds(hello.runtime.response_wait_ms, 'responseWaitMs')
        boundedMilliseconds(hello.runtime.request_timeout_ms, 'requestTimeoutMs', 1)
        return { client, hello }
      })
      this.runtimes.set(id, runtime)
    }
    return runtime
  }

  release(id: string): Promise<void> {
    const pending = this.releasing.get(id)
    if (pending) return pending
    this.runtimes.delete(id)
    const client = this.ownedClients.get(id)
    if (!client) return Promise.resolve() // Injected clients may serve several agents.
    this.ownedClients.delete(id)
    const released = Promise.resolve(client.close()).finally(() => {
      this.clients.delete(client)
      this.releasing.delete(id)
    })
    this.releasing.set(id, released)
    return released
  }

  async close(): Promise<void> {
    await Promise.all([...this.clients].map(client => client.close()))
    this.clients.clear()
  }

  private directory(id: string): string {
    const path = join(this.root, createHash('sha256').update(id).digest('hex'))
    try {
      mkdirSync(path, { recursive: true, mode: 0o700 })
      const stat = lstatSync(path)
      if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()) throw privateFailure()
      return path
    } catch { throw privateFailure() }
  }

  private createPrivateFile(path: string, contents: string): void {
    let descriptor: number | undefined
    try {
      descriptor = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600)
      writeFileSync(descriptor, contents)
      fsyncSync(descriptor)
      const directory = openSync(dirname(path), constants.O_RDONLY)
      try { fsyncSync(directory) } finally { closeSync(directory) }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw privateFailure()
    } finally { if (descriptor !== undefined) closeSync(descriptor) }
  }
}
