/**
 * The process-wide audit ring: a bounded, newest-first buffer of gateway
 * decisions, mirrored from the per-session durable log for the browser half
 * and for same-process consumers (summary panels, tests).
 *
 * The durable source of truth is the session log (`permission/gateway-decision`
 * events); the ring is a convenience projection and can be discarded freely.
 *
 * @module agent-permission-gateway/audit
 */

import { randomUUID } from 'node:crypto'
import type { GatewayDecisionEventData, PermissionAuditEntry, RiskAssessment } from './types.ts'

/** A bounded ring buffer of audit entries, newest first. */
export class AuditRing {
  private readonly entries: PermissionAuditEntry[] = []

  /**
   * @param capacity - maximum number of entries retained (default 500).
   */
  constructor(private readonly capacity = 500) {}

  /**
   * Record one decision.
   * @param entry - the entry to record (id/ts defaulted when absent).
   * @returns the stored entry.
   */
  push(entry: PermissionAuditEntry): PermissionAuditEntry {
    const stored: PermissionAuditEntry = {
      ...entry,
      id: entry.id ?? randomUUID(),
      ts: entry.ts ?? Date.now(),
    }
    this.entries.unshift(stored)
    if (this.entries.length > this.capacity) {
      this.entries.length = this.capacity
    }
    return stored
  }

  /** The most recent entries, newest first. */
  recent(limit = this.capacity): PermissionAuditEntry[] {
    return this.entries.slice(0, limit)
  }

  /** All entries, newest first. */
  all(): PermissionAuditEntry[] {
    return [...this.entries]
  }

  /** Clear the ring. */
  clear(): void {
    this.entries.length = 0
  }

  /** Current number of entries. */
  get size(): number {
    return this.entries.length
  }
}

/**
 * Build a session-event payload from an audit entry (the ring-level fields
 * `id`/`ts`/`sessionId` are derived at append time on the host).
 */
export function toEventData(entry: PermissionAuditEntry): GatewayDecisionEventData {
  return {
    ...(entry.callId !== undefined ? { callId: entry.callId } : {}),
    tool: entry.tool,
    risk: entry.risk,
    decision: entry.decision,
    ...(entry.ruleId !== undefined ? { ruleId: entry.ruleId } : {}),
    ...(entry.grantId !== undefined ? { grantId: entry.grantId } : {}),
    granted: entry.granted,
    ...(entry.reason !== undefined ? { reason: entry.reason } : {}),
  }
}

/** A minimal audit entry factory for tests and adapters. */
export interface AuditEntryInput {
  readonly ts?: number
  readonly sessionId?: string
  readonly callId?: string
  readonly tool: string
  readonly risk: RiskAssessment
  readonly decision: PermissionAuditEntry['decision']
  readonly ruleId?: string
  readonly grantId?: string
  readonly granted: boolean
  readonly reason?: string
}
