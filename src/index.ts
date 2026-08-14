/**
 * The Agent Permission Gateway / Agent IAM plugin for dsh.
 *
 * A Cordis plugin that sits in front of every tool call:
 *
 * ```text
 *              User
 *               │
 *               ▼
 *          AI Agent
 *               │
 *       Tool / Action
 *               │
 *               ▼
 *   ┌────────────────────────┐
 *   │ Agent Permission       │
 *   │ Gateway                │
 *   ├────────────────────────┤
 *   │ Identity (WHO)         │
 *   │ Policy (WHAT/WHERE)    │
 *   │ Risk Engine (WHY/WHEN) │
 *   │ Approval (scoped)      │
 *   │ Audit                  │
 *   └──────────┬─────────────┘
 *              │
 *              ▼
 *     ALLOW / DENY / ASK
 * ```
 *
 * Wiring (all best-effort against the structural host contract in
 * `host.ts`):
 *
 * - `tools/pre-execute` — the interception point: risk + policy + grants →
 *   `allow` (delegate), `deny` (block with a reason), `ask` (the registry's
 *   own approval seam resolves it).
 * - `approval/request` — grant short-circuit: an active scoped grant
 *   resolves the ask to `allowed-once` without prompting (the "Always allow"
 *   path); anything else delegates with `next()`.
 * - session log — every decision appends `permission/gateway-decision`
 *   (log-only audit, never model-visible).
 * - `permissionGateway` service on `ctx` — summary, recent audit, grants.
 * - system prompt — a posture section so the model knows the boundary.
 * - session projection — `permissionGateway` (newest-first decisions).
 * - settings — a `permission-gateway` namespace overlay (when the host
 *   provides `ctx.settings`).
 *
 * @module agent-permission-gateway
 */

import type { EngineRequest } from './engine.ts'
import type { GrantRequest } from './grants.ts'
import { compilePolicy } from './policy.ts'
import { parseYamlObject } from './yaml.ts'
import type { ApprovalRequestLike, CordisCtxLike, PreToolDecisionLike, ToolExecutionLike } from './host.ts'
import { PermissionGatewayService } from './service.ts'
import { PROJECTION_DECISION_CAP } from './types.ts'
import type { GatewayConfig, GatewaySettings, PolicyDocument } from './types.ts'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'permission-gateway'

/** The tool registry service this plugin intercepts. */
export const inject = ['tools']

/** Cap on the pending-call fact map (callId → grant facts). */
const PENDING_CAP = 1024

/**
 * Normalize the plugin config: accept a `policy` as a plain object or as a
 * YAML string (parsed with the built-in YAML-subset parser), and fill
 * defaults.
 */
export function normalizeConfig(raw: Record<string, unknown> | undefined): GatewayConfig {
  const config: Record<string, unknown> = { ...(raw ?? {}) }
  const policy = config.policy
  if (typeof policy === 'string') {
    config.policy = parseYamlObject(policy) as PolicyDocument
  }
  return config as unknown as GatewayConfig
}

/**
 * Register the gateway plugin.
 * @param ctx - the Cordis context (structural).
 */
export function apply(ctx: CordisCtxLike): void {
  const config = normalizeConfig(ctx.config)
  const service = new PermissionGatewayService(ctx, config)

  // Register the service on ctx (best-effort).
  try {
    ctx.reflect?.provide('permissionGateway', service)
  } catch {
    // A host without `reflect` (or an already-registered name) degrades to
    // an internal service only.
  }

  // callId → grant facts for the approval answerer's short-circuit.
  const pending = new Map<string, GrantRequest>()

  // ---- tools/pre-execute: the interception point --------------------------
  ctx.on('tools/pre-execute', (exec: ToolExecutionLike, next: () => unknown): unknown => {
    const { decision, judgement, request } = service.judgeExecution(exec)

    // Remember the call's facts so the approval answerer can match grants.
    if (exec.callId !== undefined) {
      pending.set(exec.callId, grantFacts(request))
      while (pending.size > PENDING_CAP) {
        const oldest = pending.keys().next().value as string | undefined
        if (oldest === undefined) break
        pending.delete(oldest)
      }
    }

    switch (decision) {
      case 'allow':
        return next()
      case 'deny':
        return { kind: 'deny', reason: judgement.reason ?? 'denied by permission gateway' } satisfies PreToolDecisionLike
      case 'ask':
        return {
          kind: 'ask',
          ...(judgement.reason !== undefined ? { reason: judgement.reason } : {}),
        } satisfies PreToolDecisionLike
    }
  })

  // ---- approval/request: grant short-circuit (Always allow) ----------------
  if (config.grantShortCircuit !== false) {
    ctx.on('approval/request', (req: ApprovalRequestLike, next: () => unknown): unknown => {
      // Resolve only when an active scoped grant matches the pending call;
      // otherwise delegate so the host's own answerer (or fail-closed
      // default) decides.
      const facts = req.callId !== undefined ? pending.get(req.callId) : undefined
      const grant = facts !== undefined
        ? service.grants.match(facts)
        : service.grants.match({
            action: req.toolName,
            tool: req.toolName,
            ...(req.agent.session !== undefined ? { agentName: req.agent.session.id } : {}),
          })
      if (grant !== undefined) return Promise.resolve('allowed-once')
      return next()
    })
  }

  // ---- system prompt: posture section -------------------------------------
  try {
    ctx.systemPrompt?.context?.({
      name: 'permission-gateway:posture',
      order: 120,
      text: () => {
        const summary = service.summary()
        return `Permission gateway posture: default ${summary.defaultDecision}, risk ceiling ${summary.denyRiskAbove}, ${summary.ruleCount} policy rules active. Calls the gateway denies cannot run; calls it approves run without further prompting.`
      },
    })
  } catch {
    // optional
  }

  // ---- session projection: permissionGateway ------------------------------
  try {
    const registry = ctx.sessionProjections
    if (registry?.register !== undefined) {
      registry.register({
        key: 'permissionGateway',
        schema: { parse: (value: unknown) => value },
        stateVersion: 1,
        init: () => ({ decisions: [] as unknown[] }),
        apply: (state: { decisions: unknown[] }, event: { type: string; data?: unknown }) => {
          if (event.type !== 'permission/gateway-decision') return state
          const decisions = [{ ...(event.data as object), ts: Date.now() }, ...state.decisions]
          if (decisions.length > PROJECTION_DECISION_CAP) decisions.length = PROJECTION_DECISION_CAP
          return { decisions }
        },
        view: (state: { decisions: unknown[] }) => ({ decisions: state.decisions }),
      })
    }
  } catch {
    // optional
  }

  // ---- settings namespace overlay ------------------------------------------
  try {
    const settings = ctx.settings
    if (settings?.register !== undefined) {
      const permissiveSchema = Object.assign(
        (value: unknown) => value,
        { toJSON: () => ({ type: 'object' }) },
      )
      const base = {
        policy: config.policy,
        default_decision: config.defaultDecision,
        deny_risk_above: config.denyRiskAbove,
      }
      const scope = settings.register('permission-gateway', permissiveSchema, {
        base,
        applies: 'live',
      }) as unknown as {
        get(): Record<string, unknown>
        watch(callback: (next: Record<string, unknown>) => void): () => void
      }
      const applyOverlay = (value: Record<string, unknown>): void => {
        service.setOverlay(overlayFromSettings(value))
      }
      applyOverlay(scope.get())
      scope.watch(next => applyOverlay(next))
    }
  } catch {
    // optional
  }
}

/** Build grant-store facts from an engine request. */
function grantFacts(request: EngineRequest): GrantRequest {
  return {
    action: request.signals.what.action,
    tool: request.tool,
    ...(request.signals.where.resource !== undefined ? { resource: request.signals.where.resource } : {}),
    ...(request.signals.where.branch !== undefined ? { branch: request.signals.where.branch } : {}),
    ...(request.signals.who.agentName !== undefined ? { agentName: request.signals.who.agentName } : {}),
  }
}

/** Convert a settings-namespace section into a gateway settings overlay. */
function overlayFromSettings(value: Record<string, unknown>): GatewaySettings | undefined {
  const policy = value.policy
  if (typeof policy === 'string') {
    return compilePolicy(parseYamlObject(policy) as PolicyDocument, {}).settings
  }
  if (policy !== undefined && typeof policy === 'object') {
    return compilePolicy(policy as PolicyDocument, {}).settings
  }
  if (value.rules !== undefined || value.default_decision !== undefined || value.deny_risk_above !== undefined) {
    const rules = Array.isArray(value.rules) ? (value.rules as GatewaySettings['rules']) : []
    return {
      rules,
      defaultDecision: (value.default_decision as GatewaySettings['defaultDecision']) ?? 'ask',
      denyRiskAbove: typeof value.deny_risk_above === 'number' ? value.deny_risk_above : 80,
    }
  }
  return undefined
}

export { PermissionGatewayService }
export default { name, inject, apply }
