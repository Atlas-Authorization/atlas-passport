import {
  AtlasBackend,
  type AtlasBackendOptions,
  type AuthorizedSession,
  type Jwks,
  type SessionClaims,
  type VerifyResult,
} from '@atlasauth/backend';
import { Strategy as PassportStrategy } from 'passport-strategy';
import { type AtlasProfile, type VerifiedCallback, toError } from './types';
import { normalizeOrigin, profileFromClaims } from './util';

/**
 * Options for {@link AtlasJwtStrategy}. The verifier it wraps is
 * `@atlasauth/backend`'s {@link AtlasBackend}, so these mirror that contract:
 * provide `domain` (the simplest case) or spell out `issuer` + a key source.
 */
export interface AtlasJwtStrategyOptions {
  /**
   * The Atlas instance origin, e.g. `id.atlasauth.net` or
   * `https://id.atlasauth.net`. Used to derive `issuer` and the JWKS URL when
   * those are not given explicitly.
   */
  domain?: string;
  /** Expected `iss`. Defaults to the normalized `domain`. Required if `domain` is absent. */
  issuer?: string;
  /** The instance publishable key (`pk_…`). Informational; not required to verify. */
  publishableKey?: string;
  /** JWKS URL. Defaults to `{domain}/.well-known/jwks.json`. Mutually exclusive with `jwks`. */
  jwksUrl?: string;
  /** A static JWKS for fully offline verification (e.g. CI). Mutually exclusive with `jwksUrl`. */
  jwks?: Jwks;
  /** §7.3 azp allowlist — reject a token minted for a different origin. */
  authorizedParties?: readonly string[];
  /** §S4 expected audience — your instance id. Opt-in; unset leaves `aud` unchecked. */
  audience?: string | readonly string[];
  /** A pre-built backend to reuse (shares the in-process JWKS cache across strategies). */
  backend?: AtlasBackend;
  /** Clock override (epoch ms), for tests. */
  now?: () => number;
  /** When true, the verify callback receives `(req, session, done)`. */
  passReqToCallback?: boolean;
}

/** The verify callback — receives the verified session, decides whether to accept it. */
export type AtlasJwtVerify = (session: AuthorizedSession, done: VerifiedCallback) => void;
export type AtlasJwtVerifyWithRequest = (
  req: unknown,
  session: AuthorizedSession,
  done: VerifiedCallback,
) => void;

/**
 * A Passport strategy for API routes that verifies an Atlas access/session token
 * carried on the request — the bearer-token half of the SDK.
 *
 * It wraps {@link AtlasBackend}, so verification is LOCAL: the JWT is checked
 * against the instance's cached JWKS with no network call on the hot path
 * (§7.3), the same guarantee `@atlasauth/express` and `@atlasauth/nextjs` give.
 * The token is read from `Authorization: Bearer <jwt>` or, failing that, the
 * `__session` cookie (header first). A missing/invalid token fails with 401.
 *
 * Register it under any name and gate a route with `passport.authenticate(...,
 * { session: false })` — these are stateless API credentials, so there is no
 * login session to persist.
 *
 * ```ts
 * passport.use('atlas-jwt', new AtlasJwtStrategy({ domain: 'id.atlasauth.net' }));
 * app.get('/api/me', passport.authenticate('atlas-jwt', { session: false }), (req, res) => {
 *   res.json({ userId: (req.user as AtlasProfile).id });
 * });
 * ```
 */
export class AtlasJwtStrategy extends PassportStrategy {
  readonly name = 'atlas-jwt';
  private readonly backend: AtlasBackend;
  private readonly verify?: AtlasJwtVerify | AtlasJwtVerifyWithRequest;
  private readonly passReqToCallback: boolean;

  constructor(
    options: AtlasJwtStrategyOptions,
    verify?: AtlasJwtVerify | AtlasJwtVerifyWithRequest,
  ) {
    super();
    this.backend = options.backend ?? new AtlasBackend(buildBackendOptions(options));
    this.verify = verify;
    this.passReqToCallback = options.passReqToCallback ?? false;
  }

  override authenticate(req: unknown, _options?: unknown): void {
    // `authenticateRequest` reads the two legitimate carriers (header first),
    // so this strategy never re-implements token extraction.
    const request = req as { headers?: Record<string, string | undefined> | { get(name: string): string | null } };
    void this.backend
      .authenticateRequest({ headers: request.headers ?? {} })
      .then((result: VerifyResult) => this.finish(req, result))
      .catch((err: unknown) => this.error(toError(err)));
  }

  private finish(req: unknown, result: VerifyResult): void {
    if (!result.ok) {
      // A coarse reason, never which specific check failed — the same stance
      // the verifier takes, so a forger learns nothing from the challenge.
      this.fail({ message: `invalid_token: ${result.reason}` }, 401);
      return;
    }

    // `result` is the AuthorizedSession, carrying has()/protect() bound to the
    // verified claims — handed to the verify callback so a route can authorize
    // inline, or turned into a profile when there is no callback.
    if (!this.verify) {
      this.success(profileFromClaims(result.claims));
      return;
    }

    const done: VerifiedCallback = (err, user, info) => {
      if (err) return this.error(toError(err));
      if (!user) return this.fail(info ?? { message: 'rejected' }, 401);
      this.success(user, info);
    };

    try {
      if (this.passReqToCallback) {
        (this.verify as AtlasJwtVerifyWithRequest)(req, result, done);
      } else {
        (this.verify as AtlasJwtVerify)(result, done);
      }
    } catch (err) {
      this.error(toError(err));
    }
  }
}

/** Alias: the bearer-token strategy, for callers who prefer the `Bearer` name. */
export const BearerStrategy = AtlasJwtStrategy;

/** Resolve the strategy options into the backend's {@link AtlasBackendOptions}. */
function buildBackendOptions(options: AtlasJwtStrategyOptions): AtlasBackendOptions {
  const origin = options.domain ? normalizeOrigin(options.domain) : undefined;
  const issuer = options.issuer ?? origin;
  if (!issuer) {
    throw new Error('AtlasJwtStrategy needs `issuer` or `domain` — an unchecked issuer accepts any Atlas instance.');
  }

  // Exactly one key source, matching AtlasBackend's own contract: a static
  // `jwks` (offline) wins when given, otherwise a URL (explicit or derived).
  if (options.jwks !== undefined) {
    return {
      jwks: options.jwks,
      issuer,
      authorizedParties: options.authorizedParties,
      audience: options.audience,
      now: options.now,
    };
  }

  const jwksUrl = options.jwksUrl ?? (origin ? `${origin}/.well-known/jwks.json` : undefined);
  if (!jwksUrl) {
    throw new Error('AtlasJwtStrategy needs a key source: pass `domain`, `jwksUrl`, or a static `jwks`.');
  }

  return {
    jwksUrl,
    issuer,
    authorizedParties: options.authorizedParties,
    audience: options.audience,
    now: options.now,
  };
}

export type { AtlasProfile, SessionClaims };
