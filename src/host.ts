/**
 * The structural host contract: the minimal shapes the plugin needs from the
 * dsh harness (Cordis runtime, tool registry, approval seam, session log).
 *
 * The plugin is deliberately written against these structural types instead
 * of importing the harness packages, so it compiles and tests standalone and
 * still type-checks when mounted into a real dsh `Context` (duck typing:
 * the harness's richer types are assignable to these).
 *
 * @module agent-permission-gateway/host
 */

// ---------------------------------------------------------------------------
// Tool registry
// ---------------------------------------------------------------------------

/** The part of a tool execution the gateway reads. */
export interface ToolExecutionLike {
  readonly callId: string
  readonly rootCallId?: string
  readonly name: string
  readonly arguments: unknown
  readonly agent?: AgentLike
  readonly signal?: AbortSignal
}

/** The `tools/pre-execute` waterfall's decision vocabulary. */
export type PreToolDecisionLike =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string }
  | { kind: 'ask'; reason?: string }

// ---------------------------------------------------------------------------
// Agent and session
// ---------------------------------------------------------------------------

/** A minimal session log event. */
export interface SessionEventLike {
  readonly type: string
  readonly data?: {
    readonly content?: unknown
    readonly text?: string
  }
}

/** A minimal session. */
export interface SessionLike {
  readonly id: string
  readonly events: readonly SessionEventLike[]
  append(type: string, data: unknown): void
}

/** A minimal live agent. */
export interface AgentLike {
  readonly id: string
  readonly session: SessionLike
  readonly options?: { readonly name?: string }
}

// ---------------------------------------------------------------------------
// Approval seam
// ---------------------------------------------------------------------------

/** The approval service's request shape. */
export interface ApprovalRequestLike {
  readonly agent: AgentLike
  readonly toolName: string
  readonly callId?: string
  readonly reason?: string
  readonly signal?: AbortSignal
}

/** The approval outcomes the seam returns. */
export type ApprovalOutcomeLike = 'allowed-once' | 'rejected' | 'cancelled' | 'unavailable'

/** The approval service (`ctx.get('approval')`). */
export interface ApprovalServiceLike {
  request(req: ApprovalRequestLike): Promise<ApprovalOutcomeLike>
}

// ---------------------------------------------------------------------------
// Settings and system prompt
// ---------------------------------------------------------------------------

/** The settings service the gateway optionally registers a namespace on. */
export interface SettingsServiceLike {
  register?(
    namespace: string,
    schema: unknown,
    options?: { base?: unknown; applies?: 'live' | 'restart'; validate?: (value: unknown) => void },
  ): unknown
}

/** The system-prompt service the gateway optionally contributes a section to. */
export interface SystemPromptLike {
  context?(section: {
    name: string
    order?: number
    text: string | ((context: { agent?: AgentLike }) => string)
  }): unknown
}

// ---------------------------------------------------------------------------
// Cordis context
// ---------------------------------------------------------------------------

/** A Cordis context, structurally. */
export interface CordisCtxLike {
  readonly config?: Record<string, unknown>
  on(event: string, listener: (...args: any[]) => any, options?: boolean | { prepend?: boolean }): unknown
  get<T = unknown>(name: string): T | undefined
  reflect?: { provide(name: string, value: unknown, check?: unknown): unknown }
  settings?: SettingsServiceLike
  systemPrompt?: SystemPromptLike
  sessionProjections?: {
    register?(definition: {
      key: string
      schema: unknown
      init(): unknown
      apply(state: unknown, event: SessionEventLike): unknown
      view(state: unknown): unknown
      stateVersion: number
    }): unknown
  }
}
