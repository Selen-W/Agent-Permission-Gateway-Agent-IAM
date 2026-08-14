import { describe, expect, it } from 'vitest'
import { compilePolicy } from '../src/policy.ts'
import type { PolicyDocument } from '../src/types.ts'

const DOC: PolicyDocument = {
  agent: 'coding-agent',
  operator: 'alice',
  default_decision: 'ask',
  permissions: {
    filesystem: {
      read: ['./workspace/**'],
      write: ['./workspace/**'],
      delete: ['./workspace/tmp/**'],
      deny: ['/etc/**'],
    },
    shell: {
      allow: ['git status', 'git diff', 'npm test'],
      approval: ['git commit', 'git push'],
      deny: ['sudo', 'rm -rf /'],
    },
    network: {
      allow: ['github.com', 'registry.npmjs.org'],
      deny: ['*'],
    },
    production: {
      require_approval: true,
      protected_branches: ['main', 'master', 'prod/*'],
      window: ['09:00-18:00 Mon-Fri'],
    },
  },
}

/** Build a call context for rule matching. */
function ctx(partial: {
  tool: string
  operation?: string
  command?: string
  resource?: string
  branch?: string
  production?: boolean
  kind?: string
  task?: string
}) {
  return {
    tool: partial.tool,
    args: {},
    argsText: '',
    signals: {
      who: { known: true },
      what: {
        operation: (partial.operation ?? 'unknown') as never,
        action: partial.command !== undefined ? `bash:${partial.command}` : partial.tool,
        ...(partial.command !== undefined ? { command: partial.command, program: partial.command.split(' ')[0] } : {}),
        flags: [],
      },
      where: {
        kind: (partial.kind ?? 'unknown') as never,
        ...(partial.resource !== undefined ? { resource: partial.resource } : {}),
        ...(partial.branch !== undefined ? { branch: partial.branch } : {}),
        production: partial.production ?? false,
      },
      when: { now: 0 },
      why: { relevance: 1, mismatched: false },
    },
  } as never
}

describe('compilePolicy', () => {
  it('compiles the document into ordered rules', () => {
    const compiled = compilePolicy(DOC)
    expect(compiled.settings.rules.length).toBeGreaterThan(0)
    expect(compiled.agents).toEqual(['coding-agent'])
    expect(compiled.settings.operatorName).toBe('alice')
    expect(compiled.settings.defaultDecision).toBe('ask')
    expect(compiled.productionWindow).toEqual(['09:00-18:00 Mon-Fri'])
    expect(compiled.protectedBranches).toEqual(['main', 'master', 'prod/*'])
    expect(compiled.productionRequiresApproval).toBe(true)
  })

  it('denies forbidden shell commands even when they could match allow', () => {
    const compiled = compilePolicy(DOC)
    const call = ctx({ tool: 'bash', command: 'sudo rm -rf /', operation: 'delete' })
    const match = compiled.settings.rules.find(rule => rule.match?.(call))
    expect(match?.decision).toBe('deny')
  })

  it('allows listed shell commands', () => {
    const compiled = compilePolicy(DOC)
    const call = ctx({ tool: 'bash', command: 'git status', operation: 'execute' })
    const match = compiled.settings.rules.find(rule => rule.match?.(call))
    expect(match?.decision).toBe('allow')
  })

  it('asks for approval-listed shell commands', () => {
    const compiled = compilePolicy(DOC)
    const call = ctx({ tool: 'bash', command: 'git push origin main', operation: 'write' })
    const match = compiled.settings.rules.find(rule => rule.match?.(call))
    expect(match?.decision).toBe('ask')
    expect(match?.source).toContain('approval')
  })

  it('scopes filesystem rules by operation', () => {
    const compiled = compilePolicy(DOC)
    // A delete of ./workspace/src (outside tmp) matches NO rule: the delete
    // allow-list only covers tmp, and the write allow-list is scoped to
    // write operations, so it must not let a delete through.
    const deleteCall = ctx({ tool: 'fs.delete', operation: 'delete', resource: './workspace/src/main.ts' })
    const matched = compiled.settings.rules.filter(rule => rule.match?.(deleteCall))
    expect(matched.length).toBe(0)

    // A delete inside tmp is allowed by the delete rule.
    const tmpCall = ctx({ tool: 'fs.delete', operation: 'delete', resource: './workspace/tmp/cache' })
    expect(compiled.settings.rules.find(rule => rule.match?.(tmpCall))?.decision).toBe('allow')

    // A write inside workspace is allowed by the write rule, not the delete rule.
    const writeCall = ctx({ tool: 'fs.write', operation: 'write', resource: './workspace/src/main.ts' })
    expect(compiled.settings.rules.find(rule => rule.match?.(writeCall))?.decision).toBe('allow')
  })

  it('asks for protected-branch writes', () => {
    const compiled = compilePolicy(DOC)
    const call = ctx({ tool: 'bash', command: 'git push origin main', operation: 'write', kind: 'repository', branch: 'main' })
    const match = compiled.settings.rules.find(rule => rule.match?.(call) && rule.note?.includes('protected branch'))
    expect(match?.decision).toBe('ask')
    expect(match?.note).toContain('protected branch')
  })

  it('asks for production calls under require_approval', () => {
    const compiled = compilePolicy(DOC)
    const call = ctx({ tool: 'bash', command: 'aws s3 rm s3://prod-bucket --recursive', operation: 'delete', kind: 'production', production: true })
    const match = compiled.settings.rules.find(rule => rule.match?.(call))
    expect(match?.decision).toBe('ask')
    expect(match?.note).toContain('production')
  })

  it('asks for non-workspace filesystem paths', () => {
    const compiled = compilePolicy(DOC)
    const call = ctx({ tool: 'fs.read', operation: 'read', resource: '/etc/passwd' })
    const match = compiled.settings.rules.find(rule => rule.match?.(call))
    expect(match?.decision).toBe('deny') // /etc/** deny list
  })

  it('denies network calls not on the allow list via deny "*"', () => {
    const compiled = compilePolicy(DOC)
    const call = ctx({ tool: 'http.fetch', operation: 'network', kind: 'network', resource: 'https://evil.example.com' })
    const match = compiled.settings.rules.find(rule => rule.match?.(call))
    expect(match?.decision).toBe('deny')
  })

  it('allows network calls on the allow list', () => {
    const compiled = compilePolicy(DOC)
    const call = ctx({ tool: 'http.fetch', operation: 'network', kind: 'network', resource: 'https://api.github.com/repos/x' })
    const match = compiled.settings.rules.find(rule => rule.match?.(call))
    expect(match?.decision).toBe('allow')
  })

  it('applies defaults when the document omits them', () => {
    const compiled = compilePolicy({}, { defaultDecision: 'deny', denyRiskAbove: 90 })
    expect(compiled.settings.defaultDecision).toBe('deny')
    expect(compiled.settings.denyRiskAbove).toBe(90)
    expect(compiled.settings.rules).toEqual([])
  })

  it('reads protected branches from the repository section too', () => {
    const compiled = compilePolicy({
      permissions: {
        repository: { protected_branches: ['develop', 'release/*'] },
      },
    })
    expect(compiled.protectedBranches).toEqual(['develop', 'release/*'])
    const call = ctx({ tool: 'bash', command: 'git push origin release/v1', operation: 'write', kind: 'repository', branch: 'release/v1' })
    const match = compiled.settings.rules.find(rule => rule.match?.(call) && rule.note?.includes('protected branch'))
    expect(match?.decision).toBe('ask')
  })
})
