/**
 * `@atlasauth/passport` — Passport.js strategies for Atlas.
 *
 * Two strategies, both wrapping `@atlasauth/backend` so there is one verifier and
 * one JWKS cache behind the whole SDK:
 *
 *   - {@link AtlasStrategy} — the interactive OIDC authorization-code flow (with
 *     PKCE) against the Atlas OP, for "Sign in with Atlas" browser login.
 *   - {@link AtlasJwtStrategy} (alias {@link BearerStrategy}) — verifies an Atlas
 *     access/session token on an API route, locally, no network on the hot path.
 */

export { AtlasStrategy } from './authorization-code-strategy';
export type {
  AtlasStrategyOptions,
  AtlasVerify,
  AtlasVerifyWithRequest,
} from './authorization-code-strategy';

export { AtlasJwtStrategy, BearerStrategy } from './jwt-strategy';
export type {
  AtlasJwtStrategyOptions,
  AtlasJwtVerify,
  AtlasJwtVerifyWithRequest,
} from './jwt-strategy';

export { profileFromClaims, normalizeOrigin } from './util';
export type { AtlasProfile, VerifiedCallback } from './types';

// Re-export the backend verifier and its types so an integrator can build a
// shared `AtlasBackend` (one JWKS cache) and hand it to the JWT strategy, and
// reach `SessionClaims` / `AuthorizedSession` without a second import.
export {
  AtlasBackend,
  type AtlasBackendOptions,
  type SessionClaims,
  type AuthorizedSession,
  type VerifyResult,
  type Jwks,
} from '@atlasauth/backend';
