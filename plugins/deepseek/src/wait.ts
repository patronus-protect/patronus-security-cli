import { setTimeout as delay } from 'node:timers/promises'
import type { JobParams, RuntimeClient, ScanResult } from './protocol.ts'

/** A response wait expires normally as pending; a caller cancellation never approves. */
export async function waitForScan(client: RuntimeClient, job: JobParams, milliseconds: number, signal: AbortSignal): Promise<ScanResult> {
  const deadline = Date.now() + milliseconds
  let result: ScanResult = { scan_id: job.scan_id, status: 'pending' }
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), milliseconds)
  const budget = AbortSignal.any([signal, controller.signal])
  try {
    while (Date.now() < deadline) {
      budget.throwIfAborted()
      result = await client.check(job, budget)
      if (result.status !== 'pending') return result
      const remaining = deadline - Date.now()
      if (remaining > 0) await delay(Math.min(50, remaining), undefined, { signal: budget })
    }
    return result
  } catch (error) {
    if (controller.signal.aborted && !signal.aborted) return result
    throw error
  } finally { clearTimeout(timer) }
}

export function boundedMilliseconds(value: number, label: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > 300_000) {
    throw new Error(`${label} must be an integer between ${minimum} and 300000 ms.`)
  }
  return value
}
