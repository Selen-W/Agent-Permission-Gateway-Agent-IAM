import { describe, expect, it } from 'vitest'
import { assessRisk, bandOf, RISK_FLAGS } from '../src/risk.ts'
import type { RiskSignals } from '../src/types.ts'

/** Build a signals fixture with sensible defaults. */
function signals(overrides: Partial<RiskSignals> = {}): RiskSignals {
  return {
    who: { known: true },
    what: { operation: 'read', action: 'fs:read', flags: [] },
    where: { kind: 'workspace', production: false },
    when: { now: 0 },
    why: { relevance: 1, mismatched: false },
    ...overrides,
  }
}

describe('bandOf', () => {
  it('maps scores to bands', () => {
    expect(bandOf(0)).toBe('low')
    expect(bandOf(24)).toBe('low')
    expect(bandOf(25)).toBe('medium')
    expect(bandOf(49)).toBe('medium')
    expect(bandOf(50)).toBe('high')
    expect(bandOf(74)).toBe('high')
    expect(bandOf(75)).toBe('critical')
    expect(bandOf(100)).toBe('critical')
  })
})

describe('assessRisk', () => {
  it('scores a workspace read as low', () => {
    const risk = assessRisk(signals({ what: { operation: 'read', action: 'fs:read readme.md', flags: [] } }))
    expect(risk.score).toBe(0)
    expect(risk.level).toBe('low')
  })

  it('scores a workspace write as low-medium', () => {
    const risk = assessRisk(signals({ what: { operation: 'write', action: 'fs:write main.ts', flags: [] } }))
    expect(risk.score).toBe(10)
    expect(risk.level).toBe('low')
  })

  it('scores a production deploy as critical', () => {
    const risk = assessRisk(signals({
      what: { operation: 'deploy', action: 'kubectl:apply', flags: [] },
      where: { kind: 'production', production: true },
    }))
    expect(risk.score).toBeGreaterThanOrEqual(75)
    expect(risk.level).toBe('critical')
    expect(risk.flags).toContain(RISK_FLAGS.productionAccess)
  })

  it('adds destructive-remove flag boosts', () => {
    const risk = assessRisk(signals({
      what: { operation: 'delete', action: 'bash:rm -rf ./build', flags: [RISK_FLAGS.destructiveRemove, RISK_FLAGS.broadWildcard] },
      where: { kind: 'workspace', production: false },
    }))
    expect(risk.score).toBeGreaterThanOrEqual(25 + 10) // delete base + two flags
    expect(risk.flags).toContain(RISK_FLAGS.destructiveRemove)
  })

  it('adds outside-window boost for production calls outside the window', () => {
    const risk = assessRisk(signals({
      what: { operation: 'deploy', action: 'aws:deploy', flags: [] },
      where: { kind: 'production', production: true },
      when: { now: 0, inProductionWindow: false },
    }))
    expect(risk.score).toBeGreaterThanOrEqual(45 + 20)
    expect(risk.flags).toContain(RISK_FLAGS.outsideWindow)
  })

  it('adds task-mismatch boost', () => {
    const risk = assessRisk(signals({
      what: { operation: 'delete', action: 'aws:s3 rm production-bucket', flags: [] },
      where: { kind: 'production', production: true },
      why: { task: 'fix unit tests', relevance: 0, mismatched: true },
    }))
    expect(risk.flags).toContain(RISK_FLAGS.taskMismatch)
  })

  it('adds unrecognized-principal boost and discounts the operator', () => {
    const unknown = assessRisk(signals({ who: { known: false } }))
    expect(unknown.flags).toContain(RISK_FLAGS.unrecognizedPrincipal)
    expect(unknown.score).toBeGreaterThan(0)

    const operator = assessRisk(signals({
      who: { known: true, agentName: 'alice', operatorName: 'alice' },
    }))
    expect(operator.score).toBe(0) // read base 0, operator discount −5 → clamped 0
    expect(operator.reasons.some(reason => reason.delta === -5)).toBe(true)
  })

  it('clamps scores to 0..100', () => {
    const max = assessRisk(signals({
      what: { operation: 'deploy', action: 'x', flags: [RISK_FLAGS.privilegeEscalation, RISK_FLAGS.credentialAccess, RISK_FLAGS.networkEgress, RISK_FLAGS.databaseWrite, RISK_FLAGS.broadWildcard] },
      where: { kind: 'production', production: true },
      when: { now: 0, inProductionWindow: false },
      why: { task: 'fix tests', relevance: 0, mismatched: true },
      who: { known: false },
    }))
    expect(max.score).toBe(100)
    expect(max.level).toBe('critical')
  })

  it('supports config overrides', () => {
    const risk = assessRisk(
      signals({ what: { operation: 'write', action: 'x', flags: [] } }),
      { operationBase: { write: 40 } },
    )
    expect(risk.score).toBe(40)
  })

  it('exposes explainable reasons in evaluation order', () => {
    const risk = assessRisk(signals({
      what: { operation: 'delete', action: 'bash:rm -rf /', flags: [RISK_FLAGS.destructiveRemove] },
      where: { kind: 'system', production: false },
    }))
    const dimensions = risk.reasons.map(reason => reason.dimension)
    expect(dimensions).toContain('what')
    expect(dimensions).toContain('where')
    expect(risk.reasons.every(reason => typeof reason.text === 'string')).toBe(true)
  })
})
