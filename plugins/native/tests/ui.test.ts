import assert from 'node:assert/strict'
import test from 'node:test'
import { runInNewContext } from 'node:vm'
import { homeHtml, apiHomeHtml } from '../src/ui.ts'

function preview(embedded: boolean, html = homeHtml) {
  const sent: any[] = []
  const feedback = { textContent: '' }
  const buttons = ['status', 'setup', 'dashboard', 'file', 'repo', 'url', 'server'].map(action => ({
    dataset: { action }, disabled: false, click: undefined as (() => Promise<void>) | undefined,
    addEventListener(_event: string, click: () => Promise<void>) { this.click = click },
  }))
  let onMessage: (event: any) => void
  const parent = { postMessage(message: any) {
    sent.push(message)
    if (message.id) queueMicrotask(() => onMessage({ source: parent, data: { jsonrpc: '2.0', id: message.id, result: {} } }))
  } }
  const window: any = { parent, addEventListener(_event: string, callback: typeof onMessage) { onMessage = callback } }
  if (!embedded) window.parent = window
  const script = html.match(/<script>([\s\S]*?)<\/script>/)![1]!
  runInNewContext(script, { window, document: { getElementById: () => feedback, querySelectorAll: () => buttons }, setTimeout, clearTimeout, Error, Promise, Map })
  return { sent, feedback, buttons }
}

test('home actions initialize the host and send explicit user requests without starting scans', async () => {
  const ui = preview(true)
  await ui.buttons.find(button => button.dataset.action === 'file')!.click!()
  assert.deepEqual(ui.sent.map(message => message.method), ['ui/initialize', 'ui/notifications/initialized', 'ui/message'])
  const message = ui.sent.at(-1).params
  assert.equal(message.role, 'user')
  assert.match(message.content[0].text, /Wait for my path before scanning/)
  assert.match(ui.feedback.textContent, /Request sent/)
  assert(ui.buttons.every(button => !button.disabled))
})

test('API home requires target selection and sends no scan or installation on open', async () => {
  const ui = preview(true, apiHomeHtml)
  await ui.buttons.find(button => button.dataset.action === 'repo')!.click!()
  assert.deepEqual(ui.sent.map(message => message.method), ['ui/initialize', 'ui/notifications/initialized', 'ui/message'])
  assert.match(ui.sent.at(-1).params.content[0].text, /Wait for my selection before fetching or scanning/)
  await ui.buttons.find(button => button.dataset.action === 'dashboard')!.click!()
  assert.match(ui.sent.at(-1).params.content[0].text, /https:\/\/control.patronus.studio/)
  assert.match(apiHomeHtml, /Selected content is sent to the Patronus API/)
  assert.doesNotMatch(apiHomeHtml, /Protection status has not been checked/)
})

test('standalone preview gives a readable fallback without claiming an action succeeded', async () => {
  const ui = preview(false)
  await ui.buttons.find(button => button.dataset.action === 'dashboard')!.click!()
  assert.equal(ui.sent.length, 0)
  assert.match(ui.feedback.textContent, /unavailable in this preview/)
  assert.match(ui.feedback.textContent, /Open my local Patronus Security dashboard/)
})
