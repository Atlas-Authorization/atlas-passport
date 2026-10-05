import type { SessionClaims } from '@atlasauth/backend';

/**
 * The verified identity a strategy hands to Passport's `verify` callback and,
 * absent one, straight to `done`. It is a thin, provider-shaped view over the
 * verified token claims — `id` is the subject (`sub`), with the common OIDC
 * fields lifted out for convenience and the full claim set kept on `claims`.
 */
export interface AtlasProfile {
  /** Passport's provider tag. Always `'atlas'`. */
  provider: 'atlas';
  /** The subject — the Atlas user id (`sub`). */
  id: string;
  /** The user's display name, when the token carried one (`name`). */
  displayName?: string;
  /** The primary email, when present (`email`), in Passport's `emails` shape. */
  emails?: Array<{ value: string; verified?: boolean }>;
  /** The active organization id (`org_id`), when the session has one. */
  orgId?: string;
  /** The user's role in the active organization (`org_role`), when present. */
  orgRole?: string;
  /** The full verified claim set, for anything finer-grained. */
  claims: SessionClaims;
}

/** The standard Passport verify callback — call it to accept or reject the identity. */
export type VerifiedCallback = (err: unknown, user?: unknown, info?: unknown) => void;

/**
 * Coerce whatever a `catch` or a verify callback hands us into an `Error`, which
 * is what Passport's `this.error()` expects. A thrown string or object becomes a
 * real Error rather than being dropped.
 */
export function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(typeof value === 'string' ? value : 'Atlas strategy error');
}
