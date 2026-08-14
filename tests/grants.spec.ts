import { describe, expect, it } from 'vitest'
import { GrantStore, grantMatches } from '../src/grants.ts'
import type { ApprovalGrant } from '../src/types.ts'

const NOW = 1_700_000_000_000

function grant(overrides: Partial<ApprovalGrant> = {}): ApprovalGrant {
  return {
    id: 'g1',
    action: 'git push*',
    scope: { resource: 'github.com/company/project-a', branch: 'feature/*', agent: 'coding-agent' },
    createdAt: NOW,
    expiresAt: NOW + 3_600_000, // 1 hour
    grantedBy: 'alice',
    ...overrides,
  }
}

describe('grantMatches', () => {
  it('matches inside action, resource, branch, agent, and time bounds', () => {
    const matches = grantMatches(grant(), {
      action: 'bash:git push origin feature/login',
      tool: 'bash',
      resource: 'github.com/company/project-a',
      branch: 'feature/login',
      agentName: 'coding-agent',
      now: NOW + 60_000,
    })
    expect(matches).toBe(true)
  })

  it('rejects when the resource differs', () => {
    const matches = grantMatches(grant(), {
      action: 'bash:git push origin feature/login',
      tool: 'bash',
      resource: 'github.com/company/project-b',
      branch: 'feature/login',
      agentName: 'coding-agent',
      now: NOW + 60_000,
    })
    expect(matches).toBe(false)
  })

  it('rejects when the branch differs', () => {
    const matches = grantMatches(grant(), {
      action: 'bash:git push origin main',
      tool: 'bash',
      resource: 'github.com/company/project-a',
      branch: 'main',
      agentName: 'coding-agent',
      now: NOW + 60_000,
    })
    expect(matches).toBe(false)
  })

  it('rejects when the agent differs', () => {
    const matches = grantMatches(grant(), {
      action: 'bash:git push origin feature/login',
      tool: 'bash',
      resource: 'github.com/company/project-a',
      branch: 'feature/login',
      agentName: 'other-agent',
      now: NOW + 60_000,
    })
    expect(matches).toBe(false)
  })

  it('rejects after expiry', () => {
    const matches = grantMatches(grant(), {
      action: 'bash:git push origin feature/login',
      tool: 'bash',
      resource: 'github.com/company/project-a',
      branch: 'feature/login',
      agentName: 'coding-agent',
      now: NOW + 3_700_000,
    })
    expect(matches).toBe(false)
  })

  it('honors wildcard bounds', () => {
    const wild = grant({ action: '*', scope: { resource: '**', branch: '**', agent: '*' } })
    expect(grantMatches(wild, {
      action: 'bash:anything at all',
      tool: 'bash',
      resource: 'anywhere',
      branch: 'anybranch',
      agentName: 'anyone',
      now: NOW,
    })).toBe(true)
  })

  it('drops bounds that are not specified', () => {
    const loose = grant({ action: 'git push*', scope: {} })
    expect(grantMatches(loose, {
      action: 'bash:git push origin whatever',
      tool: 'bash',
      now: NOW,
    })).toBe(true)
  })

  it('matches plain action patterns with command-prefix semantics', () => {
    const plain = grant({ action: 'git push', scope: {} })
    expect(grantMatches(plain, { action: 'bash:git push origin main', tool: 'bash', now: NOW })).toBe(true)
    expect(grantMatches(plain, { action: 'bash:git pull', tool: 'bash', now: NOW })).toBe(false)
  })
})

describe('GrantStore', () => {
  it('mints, lists, and revokes grants', () => {
    const store = new GrantStore()
    const minted = store.mint({
      action: 'git push*',
      scope: { resource: 'github.com/company/project-a' },
      durationMs: 60_000,
      grantedBy: 'alice',
      now: NOW,
    })
    expect(store.list(NOW)).toHaveLength(1)
    expect(store.revoke(minted.id)).toBe(true)
    expect(store.list(NOW)).toHaveLength(0)
  })

  it('drops expired grants on access', () => {
    const store = new GrantStore()
    // Mint relative to the real clock (the store's size getter reads it).
    store.mint({ action: '*', durationMs: 1000, grantedBy: 'alice' })
    expect(store.size).toBe(1)
    expect(store.list(Date.now() + 2000)).toHaveLength(0)
    expect(store.size).toBe(0)
  })

  it('matches through the store', () => {
    const store = new GrantStore()
    store.mint({
      action: 'git push*',
      scope: { resource: 'github.com/company/project-a', branch: 'feature/*' },
      durationMs: 3_600_000,
      grantedBy: 'alice',
      now: NOW,
    })
    const match = store.match({
      action: 'bash:git push origin feature/login',
      tool: 'bash',
      resource: 'github.com/company/project-a',
      branch: 'feature/login',
      now: NOW + 1000,
    })
    expect(match?.id).toBeDefined()
    expect(store.hasMatch({
      action: 'bash:git push origin main',
      tool: 'bash',
      resource: 'github.com/company/project-a',
      branch: 'main',
      now: NOW + 1000,
    })).toBe(false)
  })
})
