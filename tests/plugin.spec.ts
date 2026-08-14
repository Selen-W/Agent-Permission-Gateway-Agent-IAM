import { describe, expect, it } from 'vitest'
import { apply, normalizeConfig } from '../src/index.ts'
import type { AgentLike, CordisCtxLike, SessionEventLike, ToolExecutionLike } from '../src/host.ts'
import type { PermissionGatewayService } from '../src/service.ts'
import type { GatewayConfig, PolicyDocument } from '../src/types.ts'

/** A minimal in-memory session. */
function makeSession(id: string) {
  const events: SessionEventLike[] = []
  return {
    id,
    events,
    append(type: string, data: unknown) {
      events.push({ type, data: data as SessionEventLike['data'] })
    },
  }
}

/** A minimal agent. */
function makeAgent(id: string, name?: string): AgentLike {
  const session = makeSession(id)
  return {
    id,
    session,
    options: name !== undefined ? { name } : {},
  }
}

/** A mocked Cordis context that records listeners. */
function makeCtx(config?: Record<string, unknown>) {
  const listeners = new Map<string, Array<(...args: any[]) => any>>()
  const provided = new Map<string, unknown>()
  const ctx: CordisCtxLike & {
    listeners: Map<string, Array<(...args: any[]) => any>>
    provided: Map<string, unknown>
    settingsCalls: unknown[]
    promptSections: unknown[]
    projectionRegistrations: unknown[]
  } = {
    config,
    listeners,
    provided,
    settingsCalls: [],
    promptSections: [],
    projectionRegistrations: [],
    on(event, listener) {
      const list = listeners.get(event) ?? []
      list.push(listener)
      listeners.set(event, list)
      return () => {
        const current = listeners.get(event) ?? []
        listeners.set(event, current.filter(item => item !== listener))
      }
    },
    get<T>(name: string): T | undefined {
      return provided.get(name) as T | undefined
    },
    reflect: {
      provide(name, value) {
        provided.set(name, value)
      },
    },
    settings: {
      register(ns, schema, options) {
        ctx.settingsCalls.push({ ns, schema, options })
        return {
          get: () => ({ policy: undefined }),
          watch: () => () => {},
        }
      },
    },
    systemPrompt: {
      context(section) {
        ctx.promptSections.push(section)
      },
    },
    sessionProjections: {
      register(definition) {
        ctx.projectionRegistrations.push(definition)
      },
    },
  }
  return ctx
}

/** Dispatch one `approval/request` through the gateway listener. */
async function approvalRequest(
  ctx: ReturnType<typeof makeCtx>,
  req: { agent: ReturnType<typeof makeAgent>; toolName: string; callId?: string },
) {
  const listener = ctx.listeners.get('approval/request')?.[0]!
  let delegated = false
  const decision = await listener(req, () => {
    delegated = true
    return Promise.resolve('unavailable')
  })
  return { decision, delegated }
}

const POLICY_YAML = `
agent: coding-agent
default_decision: ask
operator: alice
permissions:
  filesystem:
    read: ["./workspace/**"]
    write: ["./workspace/**"]
    delete: ["./workspace/tmp/**"]
  shell:
    allow: ["git status", "git diff", "npm test"]
    approval: ["git commit", "git push"]
    deny: ["sudo", "rm -rf /"]
  network:
    allow: ["github.com", "registry.npmjs.org"]
    deny: ["*"]
  production:
    require_approval: true
`

describe('permission-gateway plugin', () => {
  it('registers the service, listeners, prompt section, and projection', () => {
    const ctx = makeCtx({ policy: POLICY_YAML })
    apply(ctx)
    expect(ctx.provided.get('permissionGateway')).toBeDefined()
    expect(ctx.listeners.has('tools/pre-execute')).toBe(true)
    expect(ctx.listeners.has('approval/request')).toBe(true)
    expect(ctx.promptSections.length).toBe(1)
    expect(ctx.projectionRegistrations.length).toBe(1)
    expect(ctx.projectionRegistrations[0]).toMatchObject({ key: 'permissionGateway', stateVersion: 1 })
  })

  it('normalizes a YAML policy string from config', () => {
    const config = normalizeConfig({ policy: POLICY_YAML })
    expect((config.policy as PolicyDocument).agent).toBe('coding-agent')
    expect((config.policy as PolicyDocument).permissions?.shell?.allow).toEqual(['git status', 'git diff', 'npm test'])
  })

  it('ALLOWs a low-risk listed command and audits it', async () => {
    const ctx = makeCtx({ policy: POLICY_YAML })
    apply(ctx)
    const agent = makeAgent('s1', 'coding-agent')
    const decision = await awaitPreExecute(ctx, {
      callId: 'c1',
      name: 'bash',
      arguments: { command: 'git status' },
      agent,
    })
    expect(decision.kind).toBe('allow')
    // Audit: ring entry + session event.
    const service = ctx.provided.get('permissionGateway') as PermissionGatewayService
    expect(service.recentAudit(1)[0]?.decision).toBe('allow')
    expect(agent.session.events.some(event => event.type === 'permission/gateway-decision')).toBe(true)
  })

  it('DENYs a forbidden command with the rule reason', async () => {
    const ctx = makeCtx({ policy: POLICY_YAML })
    apply(ctx)
    const decision = await awaitPreExecute(ctx, {
      callId: 'c2',
      name: 'bash',
      arguments: { command: 'sudo apt update' },
      agent: makeAgent('s2', 'coding-agent'),
    })
    expect(decision.kind).toBe('deny')
    expect(decision.reason).toContain('sudo')
  })

  it('ASKS for an approval-listed command and appends the audit event', async () => {
    const ctx = makeCtx({ policy: POLICY_YAML })
    apply(ctx)
    const agent = makeAgent('s3', 'coding-agent')
    const decision = await awaitPreExecute(ctx, {
      callId: 'c3',
      name: 'bash',
      arguments: { command: 'git push origin main' },
      agent,
    })
    expect(decision.kind).toBe('ask')
    expect(decision.reason).toContain('git push')
    const event = agent.session.events.find(event => event.type === 'permission/gateway-decision')
    expect((event?.data as { decision: string }).decision).toBe('ask')
  })

  it('honors a scoped grant: asks once, then auto-allows matching pushes', async () => {
    const ctx = makeCtx({ policy: POLICY_YAML })
    apply(ctx)
    const agent = makeAgent('s4', 'coding-agent')
    const service = ctx.provided.get('permissionGateway') as PermissionGatewayService

    // First push: ASK.
    const first = await awaitPreExecute(ctx, {
      callId: 'c4a',
      name: 'bash',
      arguments: { command: 'git push origin feature/login' },
      agent,
    })
    expect(first.kind).toBe('ask')

    // The human mints an "always allow" grant scoped to feature/* for 1h.
    service.mintGrant({
      action: 'git push*',
      scope: { branch: 'feature/*', agent: 'coding-agent' },
      durationMs: 3_600_000,
      grantedBy: 'alice',
      reason: 'feature branch pushes approved',
    })

    // Second push (same scope): ALLOW without prompting.
    const second = await awaitPreExecute(ctx, {
      callId: 'c4b',
      name: 'bash',
      arguments: { command: 'git push origin feature/login' },
      agent,
    })
    expect(second.kind).toBe('allow')
    const audit = service.recentAudit(1)[0]
    expect(audit?.grantId).toBeDefined()

    // Push to main: still ASK (outside the grant's branch bound).
    const main = await awaitPreExecute(ctx, {
      callId: 'c4c',
      name: 'bash',
      arguments: { command: 'git push origin main' },
      agent,
    })
    expect(main.kind).toBe('ask')
  })

  it('short-circuits approval/request through an active grant and delegates otherwise', async () => {
    const ctx = makeCtx({ policy: POLICY_YAML })
    apply(ctx)
    const agent = makeAgent('s5', 'coding-agent')
    const service = ctx.provided.get('permissionGateway') as PermissionGatewayService

    // No grant yet: delegate to the host answerer.
    const before = await approvalRequest(ctx, { agent, toolName: 'bash', callId: 'c5a' })
    expect(before.delegated).toBe(true)

    service.mintGrant({ action: '*', scope: {}, durationMs: 60_000, grantedBy: 'alice' })
    const after = await approvalRequest(ctx, { agent, toolName: 'bash', callId: 'c5b' })
    expect(after.decision).toBe('allowed-once')
    expect(after.delegated).toBe(false)
  })

  it('asks for production calls under require_approval', async () => {
    const ctx = makeCtx({ policy: POLICY_YAML })
    apply(ctx)
    const decision = await awaitPreExecute(ctx, {
      callId: 'c6',
      name: 'bash',
      arguments: { command: 'aws s3 ls s3://prod-bucket' },
      agent: makeAgent('s6', 'coding-agent'),
    })
    expect(decision.kind).toBe('ask')
    expect(decision.reason).toContain('production')
  })

  it('denies production calls above the risk ceiling when no rule matches', async () => {
    const ctx = makeCtx({
      policy: 'default_decision: ask\npermissions:\n  shell:\n    allow: ["git status"]\n',
    })
    apply(ctx)
    const decision = await awaitPreExecute(ctx, {
      callId: 'c7',
      name: 'bash',
      arguments: { command: 'kubectl delete pod x --namespace=prod' },
      agent: makeAgent('s7', 'coding-agent'),
    })
    expect(decision.kind).toBe('deny')
  })

  it('surfaces a summary with rule count and posture', () => {
    const ctx = makeCtx({ policy: POLICY_YAML })
    apply(ctx)
    const service = ctx.provided.get('permissionGateway') as PermissionGatewayService
    const summary = service.summary()
    expect(summary.ruleCount).toBeGreaterThan(0)
    expect(summary.defaultDecision).toBe('ask')
    expect(summary.denyRiskAbove).toBe(80)
    expect(summary.operatorName).toBe('alice')
    expect(summary.activeGrantCount).toBe(0)
  })

  it('uses the WHY dimension: a production delete unrelated to the task is risky', async () => {
    const ctx = makeCtx({ policy: POLICY_YAML })
    apply(ctx)
    const session = makeSession('s8')
    // The agent's last instruction is about tests — a production delete is off-task.
    session.append('user/message', { content: [{ type: 'text', text: 'fix the unit tests' }] })
    const agent = { id: 's8', session, options: { name: 'coding-agent' } }
    const decision = await awaitPreExecute(ctx, {
      callId: 'c8',
      name: 'bash',
      arguments: { command: 'aws s3 rm s3://prod-bucket --recursive' },
      agent,
    })
    expect(decision.kind).toBe('ask') // production require_approval asks
    const service = ctx.provided.get('permissionGateway') as PermissionGatewayService
    const entry = service.recentAudit(1)[0]
    expect(entry?.risk.flags).toContain('action-not-in-task-scope')
  })
})

/** Run the pre-execute listener and normalize its result. */
async function awaitPreExecute(ctx: ReturnType<typeof makeCtx>, exec: ToolExecutionLike): Promise<{ kind: string; reason?: string }> {
  const listener = ctx.listeners.get('tools/pre-execute')?.[0]!
  // The waterfall `next` defaults to allow.
  const result = await listener(exec, () => Promise.resolve({ kind: 'allow' }))
  return result as { kind: string; reason?: string }
}

/** A typed config fixture guard (used by the summary test). */
void (null as unknown as GatewayConfig)
