import { describe, expect, it } from 'vitest'
import { decide, type EngineRequest } from '../src/engine.ts'
import { GrantStore } from '../src/grants.ts'
import { compilePolicy } from '../src/policy.ts'
import type { GatewaySettings, PolicyDocument } from '../src/types.ts'

const NOW = 1_700_000_000_000

/** Build an engine request for a shell call. */
function shellRequest(command: string, extra: Partial<EngineRequest> = {}): EngineRequest {
  return {
    tool: 'bash',
    args: { command },
    argsText: JSON.stringify({ command }),
    signals: {
      who: { known: true, agentName: 'coding-agent', operatorName: 'alice' },
      what: {
        operation: 'execute',
        action: `bash:${command}`,
        command,
        program: command.split(' ')[0],
        flags: [],
      },
      where: { kind: 'workspace', production: false },
      when: { now: NOW },
      why: { relevance: 1, mismatched: false },
    },
    ...extra,
  }
}

const POLICY: PolicyDocument = {
  default_decision: 'ask',
  permissions: {
    shell: {
      allow: ['git status', 'git diff', 'npm test'],
      approval: ['git commit', 'git push'],
      deny: ['sudo', 'rm -rf /'],
    },
    production: { require_approval: true },
  },
}

function settingsOf(document: PolicyDocument): GatewaySettings {
  return compilePolicy(document).settings
}

describe('decide', () => {
  it('ALLOWs a low-risk listed command', () => {
    const judgement = decide({ request: shellRequest('git status'), settings: settingsOf(POLICY), now: NOW })
    expect(judgement.decision).toBe('allow')
    expect(judgement.ruleId).toBeDefined()
    expect(judgement.risk.level).toBe('low')
  })

  it('DENYs a forbidden command regardless of risk', () => {
    const judgement = decide({ request: shellRequest('sudo rm -rf /'), settings: settingsOf(POLICY), now: NOW })
    expect(judgement.decision).toBe('deny')
    expect(judgement.reason).toContain('deny')
  })

  it('ASKS for an approval-listed command', () => {
    const judgement = decide({ request: shellRequest('git push origin main'), settings: settingsOf(POLICY), now: NOW })
    expect(judgement.decision).toBe('ask')
  })

  it('ASKS for an unlisted command under default ask', () => {
    const judgement = decide({ request: shellRequest('cat /etc/hosts'), settings: settingsOf(POLICY), now: NOW })
    expect(judgement.decision).toBe('ask')
  })

  it('DENYs high-risk unlisted commands via the risk ceiling', () => {
    // No production rule here: the risk ceiling is what blocks the call.
    // Ceiling lowered so a high-risk call (delete+production) trips it.
    const settings = { ...settingsOf({ default_decision: 'ask', permissions: { shell: { allow: ['git status'] } } }), denyRiskAbove: 70 }
    const production = shellRequest('kubectl delete pod x --namespace=prod', {
      signals: {
        who: { known: true },
        what: { operation: 'delete', action: 'bash:kubectl delete pod x --namespace=prod', command: 'kubectl delete pod x --namespace=prod', program: 'kubectl', flags: [] },
        where: { kind: 'production', production: true },
        when: { now: NOW },
        why: { relevance: 1, mismatched: false },
      },
    })
    const judgement = decide({ request: production, settings, now: NOW })
    expect(judgement.decision).toBe('deny')
    expect(judgement.reason).toContain('ceiling')
  })

  it('honors defaultDecision allow', () => {
    const settings = { ...settingsOf(POLICY), defaultDecision: 'allow' as const }
    const judgement = decide({ request: shellRequest('cat /etc/hosts'), settings, now: NOW })
    expect(judgement.decision).toBe('allow')
  })

  it('honors defaultDecision deny (allowlist posture)', () => {
    const settings = { ...settingsOf(POLICY), defaultDecision: 'deny' as const }
    const judgement = decide({ request: shellRequest('cat /etc/hosts'), settings, now: NOW })
    expect(judgement.decision).toBe('deny')
    expect(judgement.reason).toContain('no policy rule')
  })

  it('short-circuits ask through a matching grant', () => {
    const grants = new GrantStore()
    grants.mint({
      action: 'git push*',
      scope: { branch: 'feature/*' },
      durationMs: 3_600_000,
      grantedBy: 'alice',
      now: NOW,
    })
    const judgement = decide({
      request: shellRequest('git push origin feature/login', {
        signals: {
          who: { known: true },
          what: { operation: 'write', action: 'bash:git push origin feature/login', command: 'git push origin feature/login', program: 'git', flags: [] },
          where: { kind: 'repository', branch: 'feature/login', production: false },
          when: { now: NOW },
          why: { relevance: 1, mismatched: false },
        },
      }),
      settings: settingsOf(POLICY),
      grants,
      now: NOW,
    })
    expect(judgement.decision).toBe('allow')
    expect(judgement.grantId).toBeDefined()
  })

  it('does not short-circuit through a grant whose branch differs', () => {
    const grants = new GrantStore()
    grants.mint({ action: 'git push*', scope: { branch: 'feature/*' }, durationMs: 3_600_000, grantedBy: 'alice', now: NOW })
    const judgement = decide({
      request: shellRequest('git push origin main', {
        signals: {
          who: { known: true },
          what: { operation: 'write', action: 'bash:git push origin main', command: 'git push origin main', program: 'git', flags: [] },
          where: { kind: 'repository', branch: 'main', production: false },
          when: { now: NOW },
          why: { relevance: 1, mismatched: false },
        },
      }),
      settings: settingsOf(POLICY),
      grants,
      now: NOW,
    })
    expect(judgement.decision).toBe('ask')
  })

  it('asks for production calls under require_approval even when risk is ceiling-clamped', () => {
    // An explicit ask rule overrides the risk ceiling.
    const production = shellRequest('aws s3 ls s3://prod-bucket', {
      signals: {
        who: { known: true },
        what: { operation: 'read', action: 'bash:aws s3 ls s3://prod-bucket', command: 'aws s3 ls s3://prod-bucket', program: 'aws', flags: [] },
        where: { kind: 'production', production: true },
        when: { now: NOW },
        why: { relevance: 1, mismatched: false },
      },
    })
    const judgement = decide({ request: production, settings: settingsOf(POLICY), now: NOW })
    expect(judgement.decision).toBe('ask')
  })

  it('produces explainable risk on every judgement', () => {
    const judgement = decide({ request: shellRequest('git push origin main'), settings: settingsOf(POLICY), now: NOW })
    expect(judgement.risk.score).toBeGreaterThanOrEqual(0)
    expect(judgement.risk.reasons.length).toBeGreaterThan(0)
  })
})
