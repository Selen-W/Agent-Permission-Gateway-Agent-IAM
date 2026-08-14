/**
 * Package-owned invariant companion for the permission gateway. Mirrors the
 * dsh convention (every guard/policy package ships an `invariant` companion
 * that reserves the package name on the invariants registry). This plugin's
 * state (audit ring, grant store) is process-local and self-healing, so the
 * companion registers no runtime invariant — it exists to keep the
 * convention uniform for loader diagnostics.
 *
 * @module agent-permission-gateway/invariant
 */

/** Cordis companion plugin name. */
export const name = 'permission-gateway-invariant'

/** The invariant registry service, when the host provides one. */
export interface InvariantRegistryLike {
  register(packageName: string, installer: () => void | Promise<void>): unknown
}

/**
 * Register the companion.
 * @param ctx - a context carrying `invariants`.
 */
export function apply(ctx: { invariants?: InvariantRegistryLike }): void {
  try {
    ctx.invariants?.register('agent-permission-gateway', () => {})
  } catch {
    // optional
  }
}

export default { name, apply }
