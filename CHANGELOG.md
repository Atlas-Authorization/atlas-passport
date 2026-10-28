# @atlasauth/passport changelog

## 0.1.1 — 2026-10-23

### Changed
- `AtlasStrategy` accepts ID tokens signed ES256 as well as RS256 (an Atlas instance can now sign with ES256).

## 0.1.0

First published release.

### Added
- `AtlasStrategy`: Passport strategy for the OIDC authorization-code flow with PKCE ("Sign in with Atlas").
- `AtlasJwtStrategy` (alias `BearerStrategy`): verifies an Atlas access/session token on API routes, locally against the cached JWKS.
- `profileFromClaims()` builds an `AtlasProfile` from session claims.
- `normalizeOrigin()` helper.
- Verify-callback types for both strategies, with and without the request.
