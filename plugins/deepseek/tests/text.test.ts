import type { Message } from '@deepseek-ai/dsh-llm'
import type { ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import { describe, expect, it } from 'vitest'
import { mcpResultText, toolResultText, userPromptText } from '../src/text.ts'

describe('DeepSeek host text visibility', () => {
  it('sees every user text block beside media and ignores non-user messages', () => {
    const messages = [
      { id: 'u1', role: 'user', source: { kind: 'user' }, content: [
        { type: 'text', text: 'first user text' },
        { type: 'image', attachment: { attachmentId: 'image', mediaType: 'image/png', bytes: 1 } },
        { type: 'text', text: '{"raw":"json text"}' },
      ] },
      { id: 'a1', role: 'assistant', source: { kind: 'model', provider: 'probe', model: 'mock' }, content: [{ type: 'text', text: 'assistant text' }] },
      { id: 'p1', role: 'user', source: { kind: 'plugin', plugin: 'fixture' }, content: [{ type: 'text', text: 'plugin text' }] },
    ] as unknown as Message[]

    expect(userPromptText(messages)).toEqual(['first user text', '{"raw":"json text"}'])
  })

  it('sees every generic tool-result text block beside media without wrapper fields', () => {
    const result = {
      isError: false,
      value: { opaque: 'not scanner input' },
      content: [
        { type: 'text', text: 'first result' },
        { type: 'image', attachment: { attachmentId: 'image', mediaType: 'image/png', bytes: 1 } },
        { type: 'text', text: '{"keep":"one raw string"}' },
      ],
      meta: { path: '/not/scanned', secretWrapperKey: 'not scanned' },
    } as unknown as ToolExecutionResult

    expect(toolResultText(result)).toEqual(['first result', '{"keep":"one raw string"}'])
  })

  it('sees ordered raw MCP content text beside media and ignores structured content', () => {
    const value = {
      content: [
        { type: 'text', text: 'first MCP text' },
        { type: 'image', data: 'opaque', mimeType: 'image/png' },
        { type: 'text', text: '{"raw":"MCP JSON text"}' },
      ],
      structuredContent: { hidden: 'not scanner input' },
    }
    expect(mcpResultText(value)).toEqual(['first MCP text', '{"raw":"MCP JSON text"}'])
    expect(toolResultText({
      isError: false,
      value,
      content: [{ type: 'text', text: 'host projection is not the raw MCP boundary' }],
    } as ToolExecutionResult)).toEqual(['first MCP text', '{"raw":"MCP JSON text"}', 'host projection is not the raw MCP boundary'])
  })

  it('keeps rendered text when canonical MCP content has no text', () => {
    expect(toolResultText({ isError: false, value: { content: [] }, content: [{ type: 'text', text: 'visible text' }] })).toEqual(['visible text'])
  })

  it('scans identical projections once without deduplicating repeated text blocks', () => {
    const content = [{ type: 'text', text: 'repeat' }, { type: 'text', text: 'repeat' }]
    expect(toolResultText({ isError: false, value: { content }, content } as ToolExecutionResult)).toEqual(['repeat', 'repeat'])
  })
})
