import { writeFile } from 'node:fs/promises'
import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import type { SessionEvent } from '@deepseek-ai/dsh-session'

// Export visible conversation and the model's system/tool context only.
// Reasoning, replay state, transport metadata, and credentials are excluded.
function visibleBlocks(blocks: ContentBlock[]): string {
  return blocks.map(block => {
    if (block.type === 'text') return block.text
    if (block.type === 'tool-call') {
      return `Tool-Aufruf: ${block.name}\n\nCall ID: ${block.id}\n\n\`\`\`json\n${block.arguments}\n\`\`\``
    }
    if (block.type === 'tool-result') {
      return `Call ID: ${block.toolCallId}; isError: ${Boolean(block.isError)}\n\n${visibleBlocks(block.content)}`
    }
    return ''
  }).filter(Boolean).join('\n\n')
}

export async function writeTranscript(
  path: string,
  events: SessionEvent[],
  model: { provider: string; model: string; scanner?: string },
): Promise<void> {
  const sections = [
    '# GPT-Test: sichtbarer Dialog',
    `Provider: ${model.provider}; Modell: ${model.model}. Scanner: ${model.scanner ?? 'simuliert'}.\n\nAus den Session-Ereignissen exportiert. Sichtbare Texte und Tool-Aufrufe/-Ergebnisse im Originalwortlaut; keine internen Reasoning-Blöcke oder Zugangsdaten. Mehrere Tool-Aufrufe unter einer GPT-Antwort wurden gemeinsam angefordert, bevor das Modell deren Ergebnisse gesehen hat.`,
  ]
  for (const event of events) {
    const timestamp = new Date(event.time).toISOString()
    if (event.type === 'user/message') {
      sections.push(`## Nutzer · ${timestamp}\n\n${visibleBlocks(event.data.content)}`)
    } else if (event.type === 'assistant/message') {
      const text = visibleBlocks(event.data.message.content)
      if (text) sections.push(`## GPT · Schritt ${event.data.step} · ${timestamp}\n\n${text}`)
    } else if (event.type === 'tool/result') {
      sections.push(`## Tool-Ergebnis · Schritt ${event.data.step} · ${timestamp}\n\n${visibleBlocks(event.data.message.content)}`)
    } else if (event.type === 'request/header') {
      const { system, tools } = event.data.header
      sections.push(`## Modellkontext · ${timestamp}\n\nSystem-Prompt: ${system || '(leer)'}\n\nTool-Schemas:\n\n\`\`\`json\n${JSON.stringify(tools ?? [], null, 2)}\n\`\`\``)
    }
  }
  await writeFile(path, sections.join('\n\n') + '\n')
}
