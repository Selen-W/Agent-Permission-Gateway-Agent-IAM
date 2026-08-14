/**
 * Agent Permission Gateway vocabulary — the public contract of the
 * permission-gateway plugin, shared by the engine, the policy compiler, the
 * audit ring, and the Cordis host adapter.
 *
 * The core decision types (`RiskLevel`, `RiskAssessment`, `GatewayDecision`,
 * `GatewayRule`, `GatewayJudgement`, `PermissionAuditEntry`, `GatewaySettings`,
 * `GatewayConfig`, `GatewaySummary`, `GatewayProjectionValue`,
 * `GatewayDecisionEventData`) deliberately mirror the shapes published by
 * `@deepseek-ai/dsh-permission-gateway/types` in the dsh harness, so this
 * implementation can be dropped into that package without breaking its
 * consumers. Everything else is the richer Agent-IAM surface: the
 * WHO/WHAT/WHERE/WHEN/WHY signal model, the declarative policy document, and
 * scoped approval grants (Action + Resource + Scope + Time).
 *
 * @module agent-permission-gateway/types
 */

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

/**
 * The gateway's five risk bands. Scores below 25 are `low`, below 50
 * `medium`, below 75 `high`, and everything at or above 75 is `critical`.
 * The `denyRiskAbove` ceiling sits inside the `critical` band by default.
 */
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

/**
 * The risk posture of one tool call: a 0–100 score, its band, and the
 * human-readable flags that raised it. Purely heuristic — a fast
 * pre-dispatch estimate, never a verdict by itself.
 */
export interface RiskAssessment {
  /** 0–100 heuristic score; higher is riskier. */
  readonly score: number
  /** The band {@link score} falls into. */
  readonly level: RiskLevel
  /** Short stable flags (`destructive-remove`, `privilege-escalation`, …) that raised the score. */
  readonly flags: readonly string[]
  /** Human-readable contributions, in evaluation order, for audit and UI. */
  readonly reasons: readonly RiskReason[]
}

/** One explainable contribution to a {@link RiskAssessment}. */
export interface RiskReason {
  /** The signal dimension that contributed (`what`, `where`, `when`, `why`, `who`). */
  readonly dimension: RiskDimension
  /** The delta applied to the score (positive raises risk, negative lowers it). */
  readonly delta: number
  /** Why the delta was applied. */
  readonly text: string
}

/** The five signal dimensions of the risk model. */
export type RiskDimension = 'what' | 'where' | 'when' | 'why' | 'who'

/**
 * What a policy rule may do with a matching call.
 * `'allow'` runs the call, `'deny'` blocks it, `'ask'` requires a one-shot
 * human approval through the approval seam (with an optional scoped grant
 * short-circuit, see {@link ApprovalGrant}).
 */
export type GatewayDecision = 'allow' | 'deny' | 'ask'

// ---------------------------------------------------------------------------
// Tool-call signals: WHO / WHAT / WHERE / WHEN / WHY
// ---------------------------------------------------------------------------

/**
 * The coarse operation class derived from a tool call. The risk engine uses
 * it as its base score; the policy document addresses it per capability.
 */
export type OperationKind = 'read' | 'write' | 'execute' | 'delete' | 'network' | 'deploy' | 'unknown'

/**
 * The coarse resource class a call targets. `production` is the most
 * sensitive; `workspace` the least.
 */
export type ResourceKind = 'workspace' | 'repository' | 'database' | 'production' | 'network' | 'system' | 'unknown'

/** WHO — identity of the caller. */
export interface WhoSignal {
  /** Agent identity (the dsh session id when the call has an agent). */
  readonly agentId?: string
  /** Agent display name (`coding-agent`, …), when known. */
  readonly agentName?: string
  /** The human principal operating the deployment, when known. */
  readonly operatorName?: string
  /** Session id the call belongs to. */
  readonly sessionId?: string
  /** Whether the caller is a recognized principal (policy-listed or the operator). */
  readonly known: boolean
}

/** WHAT — the operation itself. */
export interface WhatSignal {
  /** Coarse operation class. */
  readonly operation: OperationKind
  /** Canonical action string used by rule and grant matching (`bash:git push origin main`). */
  readonly action: string
  /** Raw command text for shell-like tools. */
  readonly command?: string
  /** The argv[0] program for shell-like tools (`git`, `rm`, `kubectl`, …). */
  readonly program?: string
  /** Stable risk flags raised by the action itself (`destructive-remove`, …). */
  readonly flags: readonly string[]
}

/** WHERE — the resource the call touches. */
export interface WhereSignal {
  /** Coarse resource class. */
  readonly kind: ResourceKind
  /** Concrete resource string (`./workspace/src/main.ts`, `github.com/company/project-a`, `s3://prod-bucket`, …). */
  readonly resource?: string
  /** Detected git branch for repository writes (`main`, `feature/*`, …). */
  readonly branch?: string
  /** Whether the call carries a production marker (`--namespace=prod`, `s3://prod-*`, …). */
  readonly production: boolean
}

/** WHEN — the wall-clock context of the call. */
export interface WhenSignal {
  /** Epoch milliseconds of the call. */
  readonly now: number
  /** Whether the call falls inside the configured production window, when one is set. */
  readonly inProductionWindow?: boolean
}

/** WHY — the agent's current task, and how well the action fits it. */
export interface WhySignal {
  /** The task text (the last human instruction), when available. */
  readonly task?: string
  /** Whether the action looks unrelated to the stated task (heuristic). */
  readonly mismatched: boolean
  /** 0..1 keyword overlap between the task and the action. */
  readonly relevance: number
}

/** The complete signal set a decision is computed from. */
export interface RiskSignals {
  readonly who: WhoSignal
  readonly what: WhatSignal
  readonly where: WhereSignal
  readonly when: WhenSignal
  readonly why: WhySignal
}

// ---------------------------------------------------------------------------
// Policy rules
// ---------------------------------------------------------------------------

/**
 * One persistent policy rule. Rules are evaluated in declaration order and
 * the first match wins; a rule with no `argContains` / `match` constraint
 * matches every call of `tool`.
 */
export interface GatewayRule {
  /** Stable rule identity, minted by the compiler. */
  readonly id: string
  /**
   * Tool name or `*`/glob pattern (`bash`, `github.*`, `*`). The pattern
   * matches the whole tool name with `*` as a wildcard.
   */
  readonly tool: string
  /**
   * Optional substring that must appear in the JSON-stringified arguments
   * for the rule to match. Kept for compatibility with the harness shape;
   * the structured {@link match} predicate is preferred.
   */
  readonly argContains?: string
  /** The rule applies only when the call's risk is at least this band. */
  readonly riskAtLeast?: RiskLevel
  /** What the rule does to a matching call. */
  readonly decision: GatewayDecision
  /** Optional structured predicate over the call context; wins over `argContains` when both are present. */
  readonly match?: (call: ToolCallContext) => boolean
  /** One human-readable sentence on why the rule exists; also the deny/ask reason. */
  readonly note?: string
  /** Policy source location (`permissions.shell.allow[2]`) for audit and UI. */
  readonly source?: string
}

/**
 * The context handed to a rule's {@link GatewayRule.match} predicate: the raw
 * call plus its extracted signals.
 */
export interface ToolCallContext {
  /** The tool name. */
  readonly tool: string
  /** The parsed arguments. */
  readonly args: unknown
  /** The lossless JSON stringification of {@link args}. */
  readonly argsText: string
  /** The extracted WHO/WHAT/WHERE/WHEN/WHY signals. */
  readonly signals: RiskSignals
  /** The current task text, when one is available. */
  readonly task?: string
}

// ---------------------------------------------------------------------------
// Decisions and audit
// ---------------------------------------------------------------------------

/**
 * The gateway's verdict on one call: a decision plus the evidence behind it.
 */
export interface GatewayJudgement {
  /** What happens to the call. */
  readonly decision: GatewayDecision
  /** The reason a client or the model sees for a `deny` / `ask` decision. */
  readonly reason?: string
  /** The rule that produced the verdict, when one matched. */
  readonly ruleId?: string
  /** The grant that short-circuited an `ask` into an `allow`, when one did. */
  readonly grantId?: string
  /** The risk assessment the verdict was computed from. */
  readonly risk: RiskAssessment
}

/**
 * One durable audit record. Written for every call that reaches the gateway,
 * appended to the owning session's log as a `permission/gateway-decision`
 * event (log-only, never model-visible) and mirrored into the process-wide
 * audit ring for the browser half.
 */
export interface PermissionAuditEntry {
  /** Fresh record identity. */
  readonly id: string
  /** Epoch milliseconds at record time. */
  readonly ts: number
  /** The owning session, when the call had an agent. */
  readonly sessionId?: string
  /** The executed call's id, correlating with the session log's `tool/call`. */
  readonly callId?: string
  /** The tool that was called. */
  readonly tool: string
  /** The risk posture the gateway computed. */
  readonly risk: RiskAssessment
  /** The gateway's decision for this call. */
  readonly decision: GatewayDecision
  /** The rule that decided the call, when one matched. */
  readonly ruleId?: string
  /** The grant that decided the call, when one matched. */
  readonly grantId?: string
  /**
   * Whether the call actually executed: `true` for an allowed call, `false`
   * for a blocked call (or one denied after an approval).
   */
  readonly granted: boolean
  /** The decision reason, when the gateway produced one. */
  readonly reason?: string
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/**
 * The resolved gateway settings: the source of truth the engine reads at
 * judgement time. The composed `Config` is the base layer; a mounted
 * settings provider overlays the user's namespace document.
 */
export interface GatewaySettings {
  /** Policy rules in evaluation order. */
  readonly rules: readonly GatewayRule[]
  /**
   * The posture for calls no rule matches: `'ask'` (default) prompts,
   * `'allow'` auto-runs, `'deny'` blocks everything not explicitly allowed
   * (an allowlist posture).
   */
  readonly defaultDecision: GatewayDecision
  /**
   * Fail-closed risk ceiling (0–100): a call whose risk score is at or above
   * this value is denied even under `defaultDecision: 'ask' | 'allow'`.
   * Explicit rules override the ceiling — a rule that matched is a person's
   * considered decision. Defaults to 80 (`critical`).
   */
  readonly denyRiskAbove: number
  /** The human operating this deployment (the gateway's principal). */
  readonly operatorName?: string
  /** The risk model knobs (production window, task-relevance, …). */
  readonly risk?: RiskModelConfig
}

/**
 * The gateway plugin's composition config. Becomes the base layer of the
 * `permission-gateway` settings namespace, so a deployment composes policy
 * here and a person (or a client) overrides it through Settings.
 */
export interface GatewayConfig extends GatewaySettings {
  /** Bounded size of the process-wide audit ring. Defaults to 500. */
  readonly ringSize?: number
  /** A declarative policy document to compile into {@link GatewaySettings.rules}. */
  readonly policy?: PolicyDocument
  /** Whether the gateway registers an `approval/request` grant short-circuit. Defaults to true. */
  readonly grantShortCircuit?: boolean
}

/**
 * Risk-model knobs the engine reads at judgement time.
 */
export interface RiskModelConfig {
  /**
   * Production window: `"HH:MM-HH:MM DDD[,DDD]"` strings (days `Mon`..`Sun`),
   * e.g. `["09:00-18:00 Mon-Fri"]`. A production call outside any window
   * raises risk and is flagged `outside-production-window`.
   */
  readonly productionWindow?: readonly string[]
  /** Whether the WHY dimension (task relevance) participates. Defaults to true. */
  readonly taskRelevance?: boolean
  /** Whether the WHO dimension (identity) participates. Defaults to true. */
  readonly identity?: boolean
  /** Per-operation base scores, overriding the built-in table. */
  readonly operationBase?: Partial<Record<OperationKind, number>>
  /** Per-resource sensitivity scores, overriding the built-in table. */
  readonly resourceSensitivity?: Partial<Record<ResourceKind, number>>
}

// ---------------------------------------------------------------------------
// Declarative policy document (the user-facing "capability boundary")
// ---------------------------------------------------------------------------

/**
 * The declarative policy document. This is the shape a deployment writes —
 * either as a YAML file (see `examples/policy.example.yaml`) or as a plain
 * object in config — to define the agent's capability boundary instead of
 * approving every call interactively.
 *
 * ```yaml
 * agent: coding-agent
 * default_decision: ask
 * permissions:
 *   filesystem:
 *     read: ["./workspace/**"]
 *     write: ["./workspace/**"]
 *     delete: ["./workspace/tmp/**"]
 *   shell:
 *     allow: ["git status", "git diff", "mvn test", "npm test"]
 *     approval: ["git commit", "git push"]
 *     deny: ["sudo", "rm -rf /"]
 *   network:
 *     allow: ["github.com", "registry.npmjs.org"]
 *     deny: ["*"]
 *   production:
 *     require_approval: true
 * ```
 */
export interface PolicyDocument {
  /** Agent name(s) this policy governs; other agents fall back to `default_decision`. */
  readonly agent?: string | readonly string[]
  /** The posture for calls no permission entry matches. */
  readonly default_decision?: GatewayDecision
  /** Fail-closed risk ceiling (0–100). */
  readonly deny_risk_above?: number
  /** The trusted human principal. */
  readonly operator?: string
  /** Production-environment knobs. */
  readonly production?: ProductionPolicy
  /** Per-capability permission entries. */
  readonly permissions?: PermissionSections
}

/** Per-capability permission sections. */
export interface PermissionSections {
  readonly filesystem?: PathPolicy
  readonly shell?: CommandPolicy
  readonly network?: HostPolicy
  readonly repository?: CommandPolicy & { readonly protected_branches?: readonly string[] }
  readonly database?: CommandPolicy
  readonly deploy?: CommandPolicy
  /** Production-resource policy; `require_approval: true` asks for every production call. */
  readonly production?: ProductionPolicy
}

/**
 * The three lists shared by every capability: what is allowed outright, what
 * needs approval, and what is forbidden. `approval` is the
 * `APPROVAL_REQUIRED` band: the gateway still asks, but the human sees the
 * policy's reason instead of a bare prompt.
 */
export interface PathPolicy {
  readonly read?: readonly string[]
  readonly write?: readonly string[]
  readonly delete?: readonly string[]
  readonly approval?: readonly string[]
  readonly deny?: readonly string[]
}

export interface CommandPolicy {
  readonly allow?: readonly string[]
  readonly approval?: readonly string[]
  readonly deny?: readonly string[]
}

export interface HostPolicy {
  readonly allow?: readonly string[]
  readonly approval?: readonly string[]
  readonly deny?: readonly string[]
}

/** Production-environment policy. */
export interface ProductionPolicy {
  /** Ask the human for every production-touching call. */
  readonly require_approval?: boolean
  /** Branch names treated as protected (`main`, `master`, `prod/*`). */
  readonly protected_branches?: readonly string[]
  /**
   * Allowed windows as `"HH:MM-HH:MM DDD[,DDD]"` strings, e.g.
   * `["09:00-18:00 Mon-Fri"]`. A production call outside any window is
   * denied (or asked, under `require_approval`).
   */
  readonly window?: readonly string[]
}

// ---------------------------------------------------------------------------
// Scoped approval grants: Approve once ≠ Always allow
// ---------------------------------------------------------------------------

/**
 * The scope of an "always allow" grant. A grant is the intersection of
 * Action + Resource + Scope + Time:
 *
 * ```text
 * approver: git push
 *   = git push
 *   + repository = github.com/company/project-a
 *   + branch     = feature/*
 *   + duration   = 1 hour
 * ```
 *
 * `ApprovalGrant` encodes exactly that: `action` is the action, `scope`
 * carries the resource and branch bounds, `expiresAt` is the time bound, and
 * `grantedBy` records who minted it.
 */
export interface GrantScope {
  /** Resource glob bound (`github.com/company/project-a`, `./workspace/**`, …). */
  readonly resource?: string
  /** Branch glob bound (`feature/*`, `main`, …). */
  readonly branch?: string
  /** Agent-name bound — the grant only applies to this agent. */
  readonly agent?: string
}

/** One minted "always allow" grant. */
export interface ApprovalGrant {
  /** Stable grant identity. */
  readonly id: string
  /**
   * The action pattern this grant covers (`git push*`, `bash:rm *tmp*`,
   * `*` for any action). Matched against the canonical action string.
   */
  readonly action: string
  /** Optional tool-name glob narrowing the grant (`bash`, `github.*`, …). */
  readonly tool?: string
  /** The resource / branch / agent bounds of the grant. */
  readonly scope: GrantScope
  /** Epoch milliseconds the grant was minted. */
  readonly createdAt: number
  /** Epoch milliseconds after which the grant no longer matches. */
  readonly expiresAt: number
  /** Who minted the grant (operator name, session id, …). */
  readonly grantedBy: string
  /** Human-readable reason for the grant. */
  readonly reason?: string
}

// ---------------------------------------------------------------------------
// Service surface
// ---------------------------------------------------------------------------

/**
 * A summary of the current posture for the browser half.
 */
export interface GatewaySummary {
  /** How many policy rules are active. */
  readonly ruleCount: number
  /** The effective default decision. */
  readonly defaultDecision: GatewayDecision
  /** The effective fail-closed risk ceiling. */
  readonly denyRiskAbove: number
  /** The configured operator name, when set. */
  readonly operatorName?: string
  /** How many grants are currently active. */
  readonly activeGrantCount: number
  /** How many audit entries the ring currently holds. */
  readonly ringSize: number
}

/**
 * The `permissionGateway` session projection value: the owning session's
 * gateway decisions in log order (the durable fold), so a browser panel can
 * render an audit view from the same data a replay reconstructs.
 */
export interface GatewayProjectionValue {
  /** The session's gateway decisions, newest first, capped by the fold. */
  readonly decisions: readonly PermissionAuditEntry[]
}

/**
 * The `permission/gateway-decision` session event payload: the audit record
 * minus the ring-level fields (`id`/`ts`/`sessionId` are derived at append
 * time on the host; the client re-derives them from the event's own seq).
 */
export interface GatewayDecisionEventData {
  /** The executed call's id, correlating with the session log's `tool/call`. */
  readonly callId?: string
  /** The tool that was called. */
  readonly tool: string
  /** The risk posture the gateway computed. */
  readonly risk: RiskAssessment
  /** The gateway's decision for this call. */
  readonly decision: GatewayDecision
  /** The rule that decided the call, when one matched. */
  readonly ruleId?: string
  /** The grant that decided the call, when one matched. */
  readonly grantId?: string
  /** Whether the call actually executed. */
  readonly granted: boolean
  /** The decision reason, when the gateway produced one. */
  readonly reason?: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Newest-first fold cap for the `permissionGateway` projection state. */
export const PROJECTION_DECISION_CAP = 50

/** Default fail-closed risk ceiling. */
export const DEFAULT_DENY_RISK_ABOVE = 80

/** Default process-wide audit ring size. */
export const DEFAULT_RING_SIZE = 500

/** Default posture for calls no rule matches. */
export const DEFAULT_DECISION: GatewayDecision = 'ask'
