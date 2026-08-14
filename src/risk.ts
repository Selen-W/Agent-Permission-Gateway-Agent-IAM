/**
 * The risk engine: a fast, explainable, heuristic pre-dispatch estimate of
 * how dangerous one tool call is, computed from the five signal dimensions
 * WHO / WHAT / WHERE / WHEN / WHY.
 *
 * The engine never decides by itself — it only produces a 0–100 score, a
 * band, and the human-readable flags and per-dimension contributions that
 * raised it. The decision engine (see `engine.ts`) combines the risk with
 * policy rules and approval grants.
 *
 * Score model (additive, clamped to 0..100):
 *
 * | dimension | contribution |
 * |---|---|
 * | WHAT  | operation base: read 0, write 10, execute 15, network 20, delete 25, deploy 30 |
 * | WHERE | resource sensitivity: workspace 0, repository 10, network 15, system 25, database 30, production 45 |
 * | WHEN  | +20 when a production call falls outside the allowed window |
 * | WHY   | +15 when the action does not fit the agent's stated task |
 * | WHO   | +5 for an unrecognized principal, −5 for the trusted operator |
 * | flags | +5 per recognized risk flag (`destructive-remove`, `privilege-escalation`, …), capped |
 *
 * @module agent-permission-gateway/risk
 */

import type {
  OperationKind,
  ResourceKind,
  RiskAssessment,
  RiskLevel,
  RiskModelConfig,
  RiskReason,
  RiskSignals,
} from './types.ts'

/** Built-in per-operation base scores. */
const OPERATION_BASE: Record<OperationKind, number> = {
  read: 0,
  write: 10,
  execute: 15,
  network: 20,
  delete: 25,
  deploy: 30,
  unknown: 5,
}

/** Built-in per-resource sensitivity scores. */
const RESOURCE_SENSITIVITY: Record<ResourceKind, number> = {
  workspace: 0,
  repository: 10,
  network: 15,
  system: 25,
  database: 30,
  production: 45,
  unknown: 5,
}

/** Extra per-flag score. */
const FLAG_BOOST = 5

/** Boost applied when a production call is outside the allowed window. */
const OUTSIDE_WINDOW_BOOST = 20

/** Boost applied when the action does not fit the stated task. */
const TASK_MISMATCH_BOOST = 15

/** Boost applied for an unrecognized principal. */
const UNKNOWN_IDENTITY_BOOST = 5

/** Discount applied for the trusted operator. */
const OPERATOR_DISCOUNT = -5

/** Map a 0–100 score to its band. */
export function bandOf(score: number): RiskLevel {
  if (score < 25) return 'low'
  if (score < 50) return 'medium'
  if (score < 75) return 'high'
  return 'critical'
}

/**
 * Assess one call's risk from its extracted signals.
 * @param signals - the WHO/WHAT/WHERE/WHEN/WHY signals.
 * @param config - risk-model knobs (production window, toggles, overrides).
 * @returns the risk assessment with explainable contributions.
 */
export function assessRisk(signals: RiskSignals, config: RiskModelConfig = {}): RiskAssessment {
  const reasons: RiskReason[] = []
  const flags = new Set<string>(signals.what.flags)

  // WHAT — operation base.
  const operationBase = config.operationBase?.[signals.what.operation]
    ?? OPERATION_BASE[signals.what.operation]
  reasons.push({
    dimension: 'what',
    delta: operationBase,
    text: `operation ${signals.what.operation} (${signals.what.action})`,
  })

  // WHERE — resource sensitivity.
  const sensitivity = config.resourceSensitivity?.[signals.where.kind]
    ?? RESOURCE_SENSITIVITY[signals.where.kind]
  reasons.push({
    dimension: 'where',
    delta: sensitivity,
    text: `resource ${signals.where.kind}${signals.where.resource ? ` (${signals.where.resource})` : ''}`,
  })
  if (signals.where.branch !== undefined) {
    flags.add('protected-branch')
  }

  // WHEN — production window.
  let whenDelta = 0
  if (signals.where.production) {
    flags.add('production-access')
    if (signals.when.inProductionWindow === false) {
      whenDelta = OUTSIDE_WINDOW_BOOST
      flags.add('outside-production-window')
      reasons.push({
        dimension: 'when',
        delta: whenDelta,
        text: 'production call outside the allowed window',
      })
    }
  }

  // WHY — task relevance.
  let whyDelta = 0
  if (config.taskRelevance !== false && signals.why.mismatched) {
    whyDelta = TASK_MISMATCH_BOOST
    flags.add('action-not-in-task-scope')
    reasons.push({
      dimension: 'why',
      delta: whyDelta,
      text: `action does not fit the stated task${signals.why.task ? ` ("${signals.why.task}")` : ''}`,
    })
  }

  // WHO — identity.
  let whoDelta = 0
  if (config.identity !== false) {
    if (!signals.who.known) {
      whoDelta = UNKNOWN_IDENTITY_BOOST
      flags.add('unrecognized-principal')
      reasons.push({ dimension: 'who', delta: whoDelta, text: 'caller is not a recognized principal' })
    } else if (signals.who.agentName !== undefined && signals.who.operatorName === signals.who.agentName) {
      whoDelta = OPERATOR_DISCOUNT
      reasons.push({ dimension: 'who', delta: whoDelta, text: 'caller is the trusted operator' })
    }
  }

  // Flags.
  let flagDelta = 0
  for (const flag of flags) {
    if (flag === 'protected-branch') continue // already reflected via sensitivity
    flagDelta += FLAG_BOOST
  }
  if (flagDelta > 0) {
    reasons.push({ dimension: 'what', delta: flagDelta, text: `risk flags: ${[...flags].join(', ')}` })
  }

  const score = clamp(operationBase + sensitivity + whenDelta + whyDelta + whoDelta + flagDelta)
  return {
    score,
    level: bandOf(score),
    flags: [...flags],
    reasons,
  }
}

/** Clamp a score into 0..100. */
function clamp(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)))
}

/**
 * Stable risk flags that tool-call extraction (and downstream audit UIs)
 * recognize.
 */
export const RISK_FLAGS = {
  /** Destructive filesystem / database removal. */
  destructiveRemove: 'destructive-remove',
  /** Privilege escalation (`sudo`, `chmod 777`, `docker exec`, …). */
  privilegeEscalation: 'privilege-escalation',
  /** Network egress (`curl`, `wget`, `nc`, …). */
  networkEgress: 'network-egress',
  /** Credential material in the call (`AKIA…`, `password=`, `.env`, …). */
  credentialAccess: 'credential-access',
  /** Database write (`DELETE FROM`, `DROP TABLE`, `UPDATE`, …). */
  databaseWrite: 'database-write',
  /** Broad destructive wildcard (`rm -rf /`, `rm -rf *`, …). */
  broadWildcard: 'broad-wildcard',
  /** Production markers in the call (`--namespace=prod`, `s3://prod-*`, …). */
  productionAccess: 'production-access',
  /** Write to a protected branch. */
  protectedBranch: 'protected-branch',
  /** Production call outside the allowed window. */
  outsideWindow: 'outside-production-window',
  /** The action does not fit the agent's stated task. */
  taskMismatch: 'action-not-in-task-scope',
  /** The caller is not a recognized principal. */
  unrecognizedPrincipal: 'unrecognized-principal',
} as const
