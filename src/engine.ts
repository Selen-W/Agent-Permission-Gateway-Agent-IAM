/**
 * The decision engine: the single place where risk, policy rules, and
 * approval grants combine into a `GatewayJudgement` (ALLOW / DENY / ASK).
 *
 * Evaluation order:
 *
 * 1. **Risk** — compute the heuristic score from the WHO/WHAT/WHERE/WHEN/WHY
 *    signals (or accept a precomputed assessment).
 * 2. **Rules** — walk the compiled rules in declaration order; the first
 *    match wins. A matched `deny` always denies, a matched `ask` asks (or
 *    short-circuits through a matching grant), a matched `allow` allows.
 * 3. **Grants** — an `ask` verdict first consults the grant store: a still
 *    valid scoped grant makes it an `allow` without prompting.
 * 4. **Default** — no rule matched: fall back to `defaultDecision`
 *    (`allow` | `ask` | `deny`), always clamped by the fail-closed
 *    `denyRiskAbove` ceiling — a call at or above the ceiling is denied
 *    even under `allow`/`ask` postures. Explicit rules override the ceiling.
 *
 * @module agent-permission-gateway/engine
 */

import { compileGlob } from './glob.ts'
import { assessRisk } from './risk.ts'
import type {
  GatewayJudgement,
  GatewayRule,
  GatewaySettings,
  RiskAssessment,
  RiskSignals,
  ToolCallContext,
} from './types.ts'
import type { GrantStore } from './grants.ts'

/** One call being decided, in engine terms. */
export interface EngineRequest {
  /** The tool name. */
  readonly tool: string
  /** The extracted signals. */
  readonly signals: RiskSignals
  /** Lossless JSON stringification of the arguments. */
  readonly argsText: string
  /** The parsed arguments (for rule predicates). */
  readonly args: unknown
}

/** Everything the engine needs to produce one judgement. */
export interface DecideInput {
  readonly request: EngineRequest
  readonly settings: GatewaySettings
  /** Precomputed risk; computed from signals when omitted. */
  readonly risk?: RiskAssessment
  /** The grant store consulted for `ask` verdicts. */
  readonly grants?: GrantStore
  /** Wall-clock now (epoch ms); defaults to `Date.now()`. */
  readonly now?: number
}

/** Deny reason template when an allow/ask rule is absent and default is deny. */
const DEFAULT_DENY_REASON = 'no policy rule allows this call'

/**
 * Decide one call.
 * @param input - the request, settings, and optional grants.
 * @returns the gateway's judgement.
 */
export function decide(input: DecideInput): GatewayJudgement {
  const { request, settings, grants } = input
  const now = input.now ?? Date.now()
  const risk = input.risk ?? assessRisk(request.signals, settings.risk ?? {})
  const context: ToolCallContext = {
    tool: request.tool,
    args: request.args,
    argsText: request.argsText,
    signals: request.signals,
    ...(request.signals.why.task !== undefined ? { task: request.signals.why.task } : {}),
  }

  // 2. Rules — first match wins.
  for (const rule of settings.rules) {
    if (!ruleMatches(rule, context, risk)) continue
    switch (rule.decision) {
      case 'deny':
        return { decision: 'deny', reason: rule.note ?? DEFAULT_DENY_REASON, ruleId: rule.id, risk }
      case 'allow':
        return { decision: 'allow', ruleId: rule.id, risk, ...(rule.note !== undefined ? { reason: rule.note } : {}) }
      case 'ask': {
        const grant = grants?.match(grantRequestOf(request, now))
        if (grant !== undefined) {
          return { decision: 'allow', ruleId: rule.id, grantId: grant.id, risk, reason: `granted by scoped grant ${grant.id}` }
        }
        return { decision: 'ask', reason: rule.note ?? 'approval required', ruleId: rule.id, risk }
      }
    }
  }

  // 4. Default posture, clamped by the risk ceiling.
  if (risk.score >= settings.denyRiskAbove) {
    return {
      decision: 'deny',
      reason: `risk score ${risk.score} is at or above the fail-closed ceiling ${settings.denyRiskAbove}`,
      risk,
    }
  }
  switch (settings.defaultDecision) {
    case 'allow':
      return { decision: 'allow', risk }
    case 'deny':
      return { decision: 'deny', reason: DEFAULT_DENY_REASON, risk }
    case 'ask': {
      const grant = grants?.match(grantRequestOf(request, now))
      if (grant !== undefined) {
        return { decision: 'allow', grantId: grant.id, risk, reason: `granted by scoped grant ${grant.id}` }
      }
      return { decision: 'ask', reason: 'no rule matched; approval required', risk }
    }
  }
}

/** Whether one rule matches the call context. */
function ruleMatches(rule: GatewayRule, context: ToolCallContext, risk: RiskAssessment): boolean {
  if (!compileGlob(rule.tool)(context.tool)) return false
  if (rule.riskAtLeast !== undefined && risk.level !== rule.riskAtLeast && !bandAtLeast(risk.level, rule.riskAtLeast)) {
    return false
  }
  if (rule.match !== undefined) return rule.match(context)
  if (rule.argContains !== undefined) return context.argsText.includes(rule.argContains)
  return true
}

/** Whether `candidate` is at or above `threshold` in the risk band order. */
function bandAtLeast(candidate: RiskAssessment['level'], threshold: RiskAssessment['level']): boolean {
  const order: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 }
  return order[candidate]! >= order[threshold]!
}

/** Build a grant-store request from an engine request. */
function grantRequestOf(request: EngineRequest, now: number) {
  return {
    action: request.signals.what.action,
    tool: request.tool,
    ...(request.signals.where.resource !== undefined ? { resource: request.signals.where.resource } : {}),
    ...(request.signals.where.branch !== undefined ? { branch: request.signals.where.branch } : {}),
    ...(request.signals.who.agentName !== undefined ? { agentName: request.signals.who.agentName } : {}),
    now,
  }
}
