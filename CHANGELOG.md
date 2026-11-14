# @atlasauth/passport changelog

## 0.1.3 — 2026-11-14

- Takes `@atlasauth/backend` as a peer dependency (`>=0.49.0 <1.0.0`) instead of pinning one exact version, so an app has a single copy of it.

## 0.1.2 — 2026-11-06

### Added
- `AtlasJwtStrategy` / `BearerStrategy` accept `previousIssuers`, so a sign-in host change does not sign users out: tokens from a listed former issuer are accepted. Absent means only `issuer` is accepted.

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
