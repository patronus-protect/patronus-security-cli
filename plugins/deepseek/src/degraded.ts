import { createUserMessage } from '@deepseek-ai/dsh-llm'

import { DEGRADED_TEXT } from './notice.ts'

export { DEGRADED_TEXT }

export const degradedMessage = (text = DEGRADED_TEXT) => createUserMessage({
  content: [{ type: 'text', text }],
  source: { kind: 'plugin', plugin: 'patronus-security' },
})
