import type { SessionClaims } from '@atlasauth/backend';
import type { AtlasProfile } from './types';

/**
 * Normalize a `domain` into an origin URL. Accepts a bare host
 * (`id.atlasauth.net`), an `https://` URL, or one with a trailing slash, and
 * always returns `https://<host>` with no trailing slash — the form the OP's
 * authorize/token/JWKS URLs are built from.
 */
export function normalizeOrigin(domain: string): string {
  const trimmed = domain.trim().replace(/\/+$/, '');
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const url = new URL(withScheme);
  return `${url.protocol}//${url.host}`;
}

/**
 * Lift the common OIDC fields out of a verified claim set into Passport's
 * provider-profile shape, keeping the full claims attached. Used when no verify
 * callback is supplied, so `req.user` is still something useful.
 */
export function profileFromClaims(claims: SessionClaims): AtlasProfile {
  const profile: AtlasProfile = {
    provider: 'atlas',
    id: claims.sub,
    claims,
  };

  const name = typeof claims.name === 'string' ? claims.name : undefined;
  if (name) profile.displayName = name;

  if (typeof claims.email === 'string' && claims.email) {
    const verified = typeof claims.email_verified === 'boolean' ? claims.email_verified : undefined;
    profile.emails = [verified === undefined ? { value: claims.email } : { value: claims.email, verified }];
  }

  if (typeof claims.org_id === 'string') profile.orgId = claims.org_id;
  if (typeof claims.org_role === 'string') profile.orgRole = claims.org_role;

  return profile;
}
