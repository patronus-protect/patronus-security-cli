export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue }

export type Host = 'codex' | 'claude'
export interface HookInput {
  hook_event_name: string
  session_id: string
  cwd: string
  tool_name?: string
  tool_use_id?: string
  tool_input?: JsonValue
  tool_response?: JsonValue
  error?: string
  [key: string]: unknown
}
/** `context` is the model-facing text of a warning when it differs from the user-facing `text`. */
export type HookDecision = { kind: 'deny' | 'replace' | 'stop' | 'warn'; text: string; context?: string }
