/**
 * The policy compiler: turns the declarative `PolicyDocument` (the
 * user-facing "capability boundary" — YAML or plain object) into the ordered
 * `GatewayRule[]` list the decision engine evaluates, plus the derived
 * settings (`defaultDecision`, `denyRiskAbove`, operator, production
 * windows, known agents).
 *
 * Rule ordering is deliberate. Within one capability, the most restrictive
 * decision wins: deny > approval > allow. Across capabilities, the
 * capability-specific lists are emitted first and the production
 * `require_approval` catch-all last, so a policy can allow a specific
 * production path explicitly and still ask for everything else
 * production-touching.
 *
 * @module agent-permission-gateway/policy
 */

import { compileGlob, matchCommand, matchHost } from './glob.ts'
import type {
  CommandPolicy,
  GatewayRule,
  GatewaySettings,
  HostPolicy,
  OperationKind,
  PathPolicy,
  PolicyDocument,
  RiskLevel,
  ToolCallContext,
} from './types.ts'
import { DEFAULT_DECISION, DEFAULT_DENY_RISK_ABOVE } from './types.ts'

/** The compiled result of a policy document. */
export interface CompiledPolicy {
  readonly settings: GatewaySettings
  /** Agent names the policy governs (for WHO recognition). */
  readonly agents: readonly string[]
  /** Production windows from the policy, for the risk model. */
  readonly productionWindow: readonly string[]
  /** Protected branch globs. */
  readonly protectedBranches: readonly string[]
  /** Whether production requires approval. */
  readonly productionRequiresApproval: boolean
}

/** Normalize a document's `agent` field into a list. */
function agentList(agent: PolicyDocument['agent']): string[] {
  if (agent === undefined) return []
  return typeof agent === 'string' ? [agent] : [...agent]
}

/**
 * Compile a policy document into rules and derived settings.
 * @param document - the declarative policy (already normalized).
 * @param base - base settings to merge under the document's values.
 * @returns the compiled policy.
 */
export function compilePolicy(document: PolicyDocument, base: Partial<GatewaySettings> = {}): CompiledPolicy {
  const rules: GatewayRule[] = []
  const protectedBranches: string[] = []
  const productionWindow: string[] = []
  let productionRequiresApproval = false
  let seq = 0

  const mint = (rule: Omit<GatewayRule, 'id'>): GatewayRule => {
    const id = `rule-${(seq += 1)}`
    const full: GatewayRule = { ...rule, id }
    rules.push(full)
    return full
  }

  const permissions = document.permissions ?? {}
  const production = permissions.production ?? document.production ?? {}

  if (production.protected_branches !== undefined) {
    protectedBranches.push(...production.protected_branches)
  }
  // The repository section may also declare protected branches; both sources
  // feed the same protected-branch rule.
  if (permissions.repository?.protected_branches !== undefined) {
    protectedBranches.push(...permissions.repository.protected_branches)
  }
  if (production.window !== undefined) {
    productionWindow.push(...production.window)
  }
  if (production.require_approval === true) {
    productionRequiresApproval = true
  }

  // ---- filesystem (operation-scoped path globs) ----------------------------
  compilePathPolicy(permissions.filesystem, mint)

  // ---- repository (git commands; more specific than the generic shell) -------
  compileCommandPolicy(permissions.repository, mint, {
    label: 'repository',
    guard: call => call.signals.what.command !== undefined && call.signals.where.kind === 'repository',
  })

  // ---- database --------------------------------------------------------------
  compileCommandPolicy(permissions.database, mint, {
    label: 'database',
    guard: call => call.signals.what.command !== undefined && call.signals.where.kind === 'database',
  })

  // ---- deploy ----------------------------------------------------------------
  compileCommandPolicy(permissions.deploy, mint, {
    label: 'deploy',
    guard: call => call.signals.what.command !== undefined
      && (call.signals.where.kind === 'system' || call.signals.where.kind === 'production')
      && call.signals.what.program !== undefined
      && DEPLOY_PROGRAMS.has(call.signals.what.program),
  })

  // ---- network (network-touching calls, shell or http tools) ----------------
  compileHostPolicy(permissions.network, mint)

  // ---- shell (any tool carrying a shell command, evaluated last: the
  //       capability-specific lists above are more specific than the generic
  //       shell list, so a `git push --force` deny in repository beats a
  //       generic `git push` approval in shell) --------------------------------
  compileCommandPolicy(permissions.shell, mint, {
    label: 'shell',
    guard: call => call.signals.what.command !== undefined,
  })

  // ---- protected branches (repository writes) ------------------------------
  if (protectedBranches.length > 0) {
    const matchers = protectedBranches.map(compileGlob)
    mint({
      tool: '*',
      decision: 'ask',
      match: call => call.signals.where.kind === 'repository'
        && call.signals.where.branch !== undefined
        && matchers.some(matcher => matcher(call.signals.where.branch!)),
      note: 'writes to a protected branch require approval',
      source: 'permissions.production.protected_branches',
    })
  }

  // ---- production require_approval (catch-all, evaluated last) -------------
  if (productionRequiresApproval) {
    mint({
      tool: '*',
      decision: 'ask',
      match: call => call.signals.where.production,
      note: 'production-touching calls require approval',
      source: 'permissions.production.require_approval',
    })
  }

  const settings: GatewaySettings = {
    rules,
    defaultDecision: document.default_decision ?? base.defaultDecision ?? DEFAULT_DECISION,
    denyRiskAbove: document.deny_risk_above ?? base.denyRiskAbove ?? DEFAULT_DENY_RISK_ABOVE,
    ...(document.operator !== undefined
      ? { operatorName: document.operator }
      : base.operatorName !== undefined
        ? { operatorName: base.operatorName }
        : {}),
    risk: {
      ...base.risk,
      ...(productionWindow.length > 0 ? { productionWindow } : {}),
    },
  }

  return {
    settings,
    agents: agentList(document.agent),
    productionWindow,
    protectedBranches,
    productionRequiresApproval,
  }
}

/** Programs treated as deploy tools by the deploy policy guard. */
const DEPLOY_PROGRAMS = new Set([
  'kubectl', 'helm', 'terraform', 'aws', 'gcloud', 'az', 'docker', 'heroku',
  'vercel', 'netlify', 'fly', 'serverless', 'sls',
])

/** One decision band with its patterns. */
interface PolicyBand {
  decision: GatewayRule['decision']
  patterns: readonly string[]
  label: string
}

/**
 * The band evaluation order for one capability, chosen by whether its deny
 * list contains a catch-all:
 *
 * - No catch-all (`deny: ["sudo", "rm -rf /"]`): the most restrictive wins —
 *   `deny > ask > allow`. A specific prohibition beats a later allow.
 * - Catch-all (`deny: ["*"]`): the deny acts as *default deny* — the
 *   allowlist pattern. `allow > ask > deny`, so the explicit allow entries
 *   are honored and everything else falls to the deny-all tail.
 */
function bandOrderFor(denyPatterns: readonly string[] | undefined): readonly GatewayRule['decision'][] {
  const hasCatchAll = (denyPatterns ?? []).some(pattern => pattern === '*' || pattern === '**')
  return hasCatchAll ? ['allow', 'ask', 'deny'] : ['deny', 'ask', 'allow']
}

/** Compile a filesystem path policy into operation-scoped rules. */
function compilePathPolicy(policy: PathPolicy | undefined, mint: (rule: Omit<GatewayRule, 'id'>) => GatewayRule): void {
  if (policy === undefined) return
  const bands: Array<PolicyBand & { operation?: OperationKind }> = [
    { decision: 'deny', patterns: policy.deny ?? [], label: 'deny' },
    { decision: 'ask', patterns: policy.approval ?? [], label: 'approval' },
    { decision: 'allow', patterns: policy.delete ?? [], label: 'delete', operation: 'delete' },
    { decision: 'allow', patterns: policy.write ?? [], label: 'write', operation: 'write' },
    { decision: 'allow', patterns: policy.read ?? [], label: 'read', operation: 'read' },
  ]
  const order = bandOrderFor(policy.deny)
  const ordered = bands
    .map(band => ({ band, rank: order.indexOf(band.decision) }))
    .sort((a, b) => a.rank - b.rank)
    .map(entry => entry.band)
  for (const band of ordered) {
    for (const pattern of band.patterns) {
      const matcher = compileGlob(pattern)
      mint({
        tool: 'fs.*',
        decision: band.decision,
        match: (call: ToolCallContext) => {
          // A filesystem rule only governs filesystem calls.
          if (call.signals.what.operation !== 'delete'
            && call.signals.what.operation !== 'write'
            && call.signals.what.operation !== 'read') {
            return false
          }
          // An allow/ask band is scoped to its own operation: the `delete`
          // allow-list must not let `fs.write` through, and vice versa.
          if (band.operation !== undefined && call.signals.what.operation !== band.operation) {
            return false
          }
          const resource = call.signals.where.resource
          if (resource === undefined) return false
          return matcher(resource)
        },
        note: `filesystem ${band.label} "${pattern}"`,
        source: `permissions.filesystem.${band.label}`,
      })
    }
  }
}

/** Compile a command policy (shell / repository / database / deploy). */
function compileCommandPolicy(
  policy: CommandPolicy | undefined,
  mint: (rule: Omit<GatewayRule, 'id'>) => GatewayRule,
  context: { label: string; guard: (call: ToolCallContext) => boolean },
): void {
  if (policy === undefined) return
  for (const decision of bandOrderFor(policy.deny)) {
    const patterns = bandPatterns(policy, decision)
    for (const pattern of patterns) {
      mint({
        tool: '*',
        decision,
        match: (call: ToolCallContext) => {
          if (!context.guard(call)) return false
          const command = call.signals.what.command
          if (command === undefined) return false
          return matchCommand(pattern, command)
        },
        note: `${context.label} ${decision} "${pattern}"`,
        source: `permissions.${context.label}.${sourceLabel(decision)}`,
      })
    }
  }
}

/** Compile a host policy (network) into rules. */
function compileHostPolicy(policy: HostPolicy | undefined, mint: (rule: Omit<GatewayRule, 'id'>) => GatewayRule): void {
  if (policy === undefined) return
  for (const decision of bandOrderFor(policy.deny)) {
    const patterns = bandPatterns(policy, decision)
    for (const pattern of patterns) {
      mint({
        tool: '*',
        decision,
        match: (call: ToolCallContext) => {
          if (call.signals.where.kind !== 'network') return false
          const resource = call.signals.where.resource
          if (resource === undefined) return false
          const host = hostOfResource(resource)
          if (host === undefined) return false
          return matchHost(pattern, host)
        },
        note: `network ${decision} "${pattern}"`,
        source: `permissions.network.${sourceLabel(decision)}`,
      })
    }
  }
}

/** The YAML field name for a decision band (`ask` → `approval`). */
function sourceLabel(decision: GatewayRule['decision']): string {
  return decision === 'ask' ? 'approval' : decision
}

/** Read the patterns of one decision band from a command/host policy. */
function bandPatterns(policy: CommandPolicy | HostPolicy, decision: GatewayRule['decision']): readonly string[] {
  switch (decision) {
    case 'allow': return policy.allow ?? []
    case 'ask': return policy.approval ?? []
    case 'deny': return policy.deny ?? []
  }
}

/** Extract the host part from a resource string. */
function hostOfResource(resource: string): string | undefined {
  const match = resource.match(/^(?:[a-z][a-z0-9+.-]*:\/\/)?([^/:\s]+)/i)
  return match ? match[1] : undefined
}

/** Risk-band ordering helper: whether `candidate` is at least `level`. */
export function riskAtLeast(level: RiskLevel): (candidate: RiskLevel) => boolean {
  const order: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 }
  const threshold = order[level]
  return (candidate: RiskLevel) => order[candidate] >= threshold
}
