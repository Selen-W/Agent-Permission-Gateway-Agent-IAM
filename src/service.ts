/**
 * The permission gateway service: the process-wide face of the plugin. It
 * owns the compiled settings, the risk engine, the grant store, the audit
 * ring, and the per-call judgement pipeline, and exposes the surface a
 * browser half or an approval answerer integrates with.
 *
 * The service is framework-agnostic: it talks to the host through the
 * structural contract in `host.ts` (tool executions, the approval seam, the
 * session log). The Cordis plugin in `index.ts` wires it to the real events.
 *
 * @module agent-permission-gateway/service
 */

import { randomUUID } from 'node:crypto'
import { AuditRing, toEventData } from './audit.ts'
import { extractCall, lastUserTask, type ToolCallLike, type ExtractOptions } from './context.ts'
import { decide, type EngineRequest } from './engine.ts'
import { GrantStore, type MintGrantInput } from './grants.ts'
import type { CordisCtxLike, ToolExecutionLike } from './host.ts'
import { compilePolicy, type CompiledPolicy } from './policy.ts'
import { assessRisk } from './risk.ts'
import type {
  ApprovalGrant,
  GatewayConfig,
  GatewayDecision,
  GatewayJudgement,
  GatewaySettings,
  GatewaySummary,
  PermissionAuditEntry,
} from './types.ts'
import { DEFAULT_RING_SIZE, PROJECTION_DECISION_CAP } from './types.ts'

/** How the service reads current settings. */
export interface SettingsProvider {
  /** The resolved settings (base config + policy document + settings overlay). */
  get(): GatewaySettings
  /** Agent names the policy recognizes (for WHO). */
  agents(): readonly string[]
  /** The production window strings, for the risk model. */
  productionWindow(): readonly string[]
}

/** A settings provider built from a resolved config. */
class ResolvedSettingsProvider implements SettingsProvider {
  readonly compiled: CompiledPolicy

  constructor(
    config: GatewayConfig,
    private readonly overlay?: GatewaySettings,
  ) {
    const base: Partial<GatewaySettings> = {
      defaultDecision: config.defaultDecision,
      denyRiskAbove: config.denyRiskAbove,
      ...(config.operatorName !== undefined ? { operatorName: config.operatorName } : {}),
      risk: config.risk,
    }
    this.compiled = compilePolicy(config.policy ?? {}, base)
  }

  get(): GatewaySettings {
    const own = this.compiled.settings
    const overlay = this.overlay
    if (overlay === undefined) return own
    return {
      rules: overlay.rules.length > 0 ? overlay.rules : own.rules,
      defaultDecision: overlay.defaultDecision ?? own.defaultDecision,
      denyRiskAbove: overlay.denyRiskAbove ?? own.denyRiskAbove,
      ...(overlay.operatorName !== undefined ? { operatorName: overlay.operatorName } : own.operatorName !== undefined ? { operatorName: own.operatorName } : {}),
      risk: { ...own.risk, ...overlay.risk },
    }
  }

  agents(): readonly string[] {
    return this.compiled.agents
  }

  productionWindow(): readonly string[] {
    return this.compiled.productionWindow
  }
}

/** Options for constructing the service. */
export interface PermissionGatewayServiceOptions {
  /** Wall-clock source; defaults to `Date.now()`. */
  readonly now?: () => number
  /** A logger for warnings. */
  readonly warn?: (message: string) => void
}

/**
 * The gateway service. One instance per plugin mount.
 */
export class PermissionGatewayService {
  readonly grants = new GrantStore()
  private readonly audit: AuditRing
  private readonly provider: SettingsProvider
  private readonly now: () => number
  private readonly warn: (message: string) => void
  /** Settings overlay applied on top of the base config (e.g. from Settings). */
  private overlay: GatewaySettings | undefined

  constructor(
    _ctx: CordisCtxLike,
    config: GatewayConfig,
    options: PermissionGatewayServiceOptions = {},
  ) {
    this.now = options.now ?? (() => Date.now())
    this.warn = options.warn ?? (() => {})
    this.audit = new AuditRing(config.ringSize ?? DEFAULT_RING_SIZE)
    this.provider = new ResolvedSettingsProvider(config, this.overlay)
  }

  /** The effective settings. */
  get settings(): GatewaySettings {
    return this.provider.get()
  }

  /** Replace the settings overlay (called by a Settings namespace watcher). */
  setOverlay(overlay: GatewaySettings | undefined): void {
    this.overlay = overlay
  }

  /**
   * Swap the active policy document (runtime policy reload). The document is
   * compiled against the base config's posture defaults.
   * @param document - the new declarative policy.
   */
  setPolicyDocument(document: GatewayConfig['policy']): void {
    const compiled = compilePolicy(document ?? {}, {
      defaultDecision: this.settings.defaultDecision,
      denyRiskAbove: this.settings.denyRiskAbove,
      risk: this.settings.risk,
    })
    this.setOverlay(compiled.settings)
  }

  /** The agent names the policy recognizes. */
  knownAgents(): readonly string[] {
    return this.provider.agents()
  }

  /** A posture summary for UIs. */
  summary(): GatewaySummary {
    const settings = this.settings
    return {
      ruleCount: settings.rules.length,
      defaultDecision: settings.defaultDecision,
      denyRiskAbove: settings.denyRiskAbove,
      ...(settings.operatorName !== undefined ? { operatorName: settings.operatorName } : {}),
      activeGrantCount: this.grants.size,
      ringSize: this.audit.size,
    }
  }

  /** Recent audit entries, newest first. */
  recentAudit(limit = 50): PermissionAuditEntry[] {
    return this.audit.recent(limit)
  }

  // -------------------------------------------------------------------------
  // Judgement pipeline
  // -------------------------------------------------------------------------

  /**
   * Judge one tool call without recording anything.
   * @param call - the tool call (name + arguments).
   * @param extra - extraction options (task, identity, clock).
   * @returns the gateway's judgement.
   */
  judgeCall(call: ToolCallLike, extra: ExtractOptions = {}): GatewayJudgement {
    const extracted = extractCall(call, this.extractOptions(extra))
    const request: EngineRequest = {
      tool: call.name,
      signals: extracted.signals,
      argsText: extracted.argsText,
      args: call.arguments,
    }
    return decide({ request, settings: this.settings, grants: this.grants, now: this.now() })
  }

  /**
   * Judge a live tool execution, record the audit entry, and return the
   * `tools/pre-execute` decision for it.
   * @param exec - the execution.
   * @returns the pre-execute decision plus the judgement and engine request.
   */
  judgeExecution(exec: ToolExecutionLike): {
    decision: GatewayDecision
    judgement: GatewayJudgement
    request: EngineRequest
  } {
    const now = this.now()
    const extracted = extractCall(
      { name: exec.name, arguments: exec.arguments },
      this.extractOptions({ agent: exec.agent }),
    )
    const request: EngineRequest = {
      tool: exec.name,
      signals: extracted.signals,
      argsText: extracted.argsText,
      args: exec.arguments,
    }
    const judgement = decide({ request, settings: this.settings, grants: this.grants, now })

    const entry: PermissionAuditEntry = {
      id: randomUUID(),
      ts: now,
      ...(exec.agent !== undefined ? { sessionId: exec.agent.session.id } : {}),
      ...(exec.callId !== undefined ? { callId: exec.callId } : {}),
      tool: exec.name,
      risk: judgement.risk,
      decision: judgement.decision,
      ...(judgement.ruleId !== undefined ? { ruleId: judgement.ruleId } : {}),
      ...(judgement.grantId !== undefined ? { grantId: judgement.grantId } : {}),
      granted: judgement.decision === 'allow',
      ...(judgement.reason !== undefined ? { reason: judgement.reason } : {}),
    }
    this.audit.push(entry)
    this.appendSessionEvent(exec, entry)

    if (judgement.decision === 'allow') return { decision: 'allow', judgement, request }
    if (judgement.decision === 'deny') {
      return { decision: 'deny', judgement, request }
    }
    return { decision: 'ask', judgement, request }
  }

  /** Compute the risk of a call (for previews / UIs). */
  previewRisk(call: ToolCallLike, extra: ExtractOptions = {}): PermissionAuditEntry['risk'] {
    const extracted = extractCall(call, this.extractOptions(extra))
    return assessRisk(extracted.signals, this.settings.risk ?? {})
  }

  // -------------------------------------------------------------------------
  // Grants ("always allow", scoped)
  // -------------------------------------------------------------------------

  /** Mint a scoped grant. */
  mintGrant(input: MintGrantInput): ApprovalGrant {
    return this.grants.mint(input)
  }

  /** Revoke a grant. */
  revokeGrant(id: string): boolean {
    return this.grants.revoke(id)
  }

  /** List active grants. */
  listGrants(): ApprovalGrant[] {
    return this.grants.list(this.now())
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  /** Build extraction options from identity + task sources. */
  private extractOptions(extra: ExtractOptions & { agent?: ToolExecutionLike['agent'] }): ExtractOptions {
    const settings = this.settings
    const agent = extra.agent
    const sessionId = extra.sessionId ?? agent?.session.id
    const agentName = extra.agentName ?? agent?.options?.name
    const events = agent?.session.events
    const task = extra.task ?? (events !== undefined ? lastUserTask(events) : undefined)
    return {
      now: this.now(),
      ...(task !== undefined ? { task } : {}),
      ...(agent?.id !== undefined ? { agentId: agent.id } : {}),
      ...(agentName !== undefined ? { agentName } : {}),
      ...(settings.operatorName !== undefined ? { operatorName: settings.operatorName } : {}),
      ...(sessionId !== undefined ? { sessionId } : {}),
      ...(this.provider.productionWindow().length > 0 ? { productionWindow: this.provider.productionWindow() } : {}),
      knownAgents: this.knownAgents(),
    }
  }

  /** Append the audit record to the owning session's durable log. */
  private appendSessionEvent(exec: ToolExecutionLike, entry: PermissionAuditEntry): void {
    const session = exec.agent?.session
    if (session === undefined) return
    try {
      session.append('permission/gateway-decision', toEventData(entry))
    } catch (error) {
      this.warn(`permission-gateway: failed to append session audit event: ${String(error)}`)
    }
  }
}

/** The fold the session projection uses (kept in sync with the harness types). */
export { PROJECTION_DECISION_CAP }

/** Re-export for the plugin entry. */
export type { GatewayConfig, GatewaySettings }
