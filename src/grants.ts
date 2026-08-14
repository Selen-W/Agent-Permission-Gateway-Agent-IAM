/**
 * Scoped approval grants: the "Always allow" side of the approval flow.
 *
 * The core design rule of the gateway is
 *
 * ```text
 * Approve once ≠ Always allow
 * ```
 *
 * An `allowed-once` approval resolves exactly one call and records no state.
 * An "always allow" decision is NOT a blanket — it is a bounded grant with
 * the same shape as the permission question itself:
 *
 * ```text
 * action   = git push
 * resource = github.com/company/project-a   (scope)
 * branch   = feature/*                       (scope)
 * agent    = coding-agent                    (scope)
 * time     = now + 1 hour                    (expiry)
 * ```
 *
 * A grant matches a call only when the call's action, resource, branch, and
 * agent all fall inside the grant's bounds AND the grant has not expired.
 * Expired grants are dropped lazily on every access.
 *
 * @module agent-permission-gateway/grants
 */

import { randomUUID } from 'node:crypto'
import { compileGlob, matchCommand } from './glob.ts'
import type { ApprovalGrant, GrantScope } from './types.ts'

/** The request side a grant is matched against. */
export interface GrantRequest {
  /** Canonical action string (`bash:git push origin main`). */
  readonly action: string
  /** Tool name. */
  readonly tool: string
  /** Resource string, when one was resolved. */
  readonly resource?: string
  /** Branch, when one was detected. */
  readonly branch?: string
  /** Agent name, when known. */
  readonly agentName?: string
  /** Wall-clock now (epoch ms); defaults to `Date.now()`. */
  readonly now?: number
}

/** Input for minting a new grant. */
export interface MintGrantInput {
  /** The action pattern this grant covers (`git push*`, `*`). */
  readonly action: string
  /** Optional tool-name glob narrowing the grant. */
  readonly tool?: string
  /** The resource / branch / agent bounds. */
  readonly scope?: GrantScope
  /** Grant lifetime in milliseconds. */
  readonly durationMs: number
  /** Who minted the grant (operator name, session id, …). */
  readonly grantedBy: string
  /** Human-readable reason. */
  readonly reason?: string
  /** Wall-clock now (epoch ms); defaults to `Date.now()`. */
  readonly now?: number
}

/** An in-memory store of active grants, bounded by expiry. */
export class GrantStore {
  private readonly grants = new Map<string, ApprovalGrant>()

  /**
   * Mint a grant and store it.
   * @param input - the grant specification.
   * @returns the stored grant.
   */
  mint(input: MintGrantInput): ApprovalGrant {
    const now = input.now ?? Date.now()
    const grant: ApprovalGrant = {
      id: randomUUID(),
      action: input.action,
      ...(input.tool !== undefined ? { tool: input.tool } : {}),
      scope: input.scope ?? {},
      createdAt: now,
      expiresAt: now + input.durationMs,
      grantedBy: input.grantedBy,
      ...(input.reason !== undefined ? { reason: input.reason } : {}),
    }
    this.grants.set(grant.id, grant)
    return grant
  }

  /**
   * Revoke a grant by id.
   * @param id - the grant id.
   * @returns whether a grant was removed.
   */
  revoke(id: string): boolean {
    return this.grants.delete(id)
  }

  /**
   * All grants, expired ones dropped first.
   */
  list(now = Date.now()): ApprovalGrant[] {
    this.dropExpired(now)
    return [...this.grants.values()]
  }

  /**
   * The first active grant matching the request, if any.
   * @param request - the call being decided.
   * @returns the matching grant, or undefined.
   */
  match(request: GrantRequest): ApprovalGrant | undefined {
    const now = request.now ?? Date.now()
    this.dropExpired(now)
    for (const grant of this.grants.values()) {
      if (grantMatches(grant, request, now)) return grant
    }
    return undefined
  }

  /** Whether any active grant matches the request. */
  hasMatch(request: GrantRequest): boolean {
    return this.match(request) !== undefined
  }

  /** Number of non-expired grants. */
  get size(): number {
    this.dropExpired()
    return this.grants.size
  }

  /** Drop expired grants. */
  private dropExpired(now = Date.now()): void {
    for (const [id, grant] of this.grants) {
      if (grant.expiresAt <= now) this.grants.delete(id)
    }
  }
}

/**
 * Whether one grant covers one request: action, tool, resource, branch, and
 * agent bounds must all match, and the grant must not be expired.
 * @param grant - the grant to test.
 * @param request - the call being decided.
 * @param now - wall-clock now; defaults to `request.now`, then `Date.now()`.
 */
export function grantMatches(grant: ApprovalGrant, request: GrantRequest, now?: number): boolean {
  const effectiveNow = now ?? request.now ?? Date.now()
  if (grant.expiresAt <= effectiveNow) return false

  // Action bound (glob over the canonical action, or token command match).
  if (!actionMatches(grant.action, request.action)) return false

  // Tool bound.
  if (grant.tool !== undefined && !compileGlob(grant.tool)(request.tool)) return false

  const scope = grant.scope
  // Resource bound.
  if (scope.resource !== undefined) {
    if (request.resource === undefined) return false
    if (!compileGlob(scope.resource)(request.resource)) return false
  }
  // Branch bound.
  if (scope.branch !== undefined) {
    if (request.branch === undefined) return false
    if (!compileGlob(scope.branch)(request.branch)) return false
  }
  // Agent bound.
  if (scope.agent !== undefined) {
    if (request.agentName === undefined) return false
    if (!compileGlob(scope.agent)(request.agentName)) return false
  }
  return true
}

/**
 * Match a grant's action pattern against the canonical action string. The
 * action is `tool:command`; the pattern is matched against the command part
 * with token semantics (`git push*` matches `git push origin feature/login`,
 * a bare `*` matches everything). Non-command actions fall back to
 * token-prefix matching on the whole action string.
 */
function actionMatches(pattern: string, action: string): boolean {
  if (pattern === '*') return true
  const [, command] = splitAction(action)
  if (command !== undefined) return matchCommand(pattern, command)
  return matchCommand(pattern, action)
}

/** Split `tool:command` into its parts. */
function splitAction(action: string): [string, string | undefined] {
  const colon = action.indexOf(':')
  if (colon === -1) return [action, undefined]
  return [action.slice(0, colon), action.slice(colon + 1)]
}
