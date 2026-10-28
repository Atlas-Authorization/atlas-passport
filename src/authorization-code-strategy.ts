import { JwksCache, readKid, createPkcePair, type SessionClaims } from '@atlasauth/backend';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { Strategy as PassportStrategy } from 'passport-strategy';
import { type AtlasProfile, type VerifiedCallback, toError } from './types';
import { normalizeOrigin, profileFromClaims } from './util';

/** §7.3 clock-skew tolerance, matching the rest of the SDK. */
const CLOCK_SKEW_SECONDS = 5;

export interface AtlasStrategyOptions {
  /** The Atlas instance origin / OIDC issuer, e.g. `id.atlasauth.net`. */
  domain: string;
  /** The OIDC client id registered for this app. */
  clientID: string;
  /**
   * The client secret, for a confidential client. OMIT it for a public client
   * (an SPA/native/CLI flow) — PKCE alone proves the exchange, and shipping a
   * secret in a public client is worse than having none.
   */
  clientSecret?: string;
  /** The instance publishable key (`pk_…`). Informational. */
  publishableKey?: string;
  /** The registered redirect URI this strategy's callback handles. */
  callbackURL: string;
  /** Scopes to request. Default: `['openid', 'profile', 'email']`. */
  scope?: string | string[];
  /** Expected `iss` on the returned id_token. Defaults to the normalized `domain`. */
  issuer?: string;
  /** Override the authorization endpoint. Default `{domain}/oauth2/authorize`. */
  authorizationURL?: string;
  /** Override the token endpoint. Default `{domain}/oauth2/token`. */
  tokenURL?: string;
  /** Override the JWKS URL used to verify the id_token. Default `{domain}/.well-known/jwks.json`. */
  jwksURL?: string;
  /** Send & check the `state` parameter (CSRF). Default `true`; needs a session. */
  state?: boolean;
  /** Use PKCE (S256). Default `true`; needs a session to stash the verifier. */
  pkce?: boolean;
  /** The key under `req.session` the transaction (state + verifier) is stashed at. */
  sessionKey?: string;
  /** When true, the verify callback receives the request as its first argument. */
  passReqToCallback?: boolean;
  /** `fetch` override, for tests. */
  fetchImpl?: typeof fetch;
  /** Clock override (epoch ms), for tests. */
  now?: () => number;
}

export type AtlasVerify = (
  accessToken: string,
  refreshToken: string | undefined,
  profile: AtlasProfile,
  done: VerifiedCallback,
) => void;
export type AtlasVerifyWithRequest = (
  req: unknown,
  accessToken: string,
  refreshToken: string | undefined,
  profile: AtlasProfile,
  done: VerifiedCallback,
) => void;

interface Transaction {
  state?: string;
  codeVerifier?: string;
}

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  token_type?: string;
  expires_in?: number;
}

/**
 * A Passport strategy for interactive "Sign in with Atlas" — the OIDC
 * authorization-code flow (with PKCE) against the Atlas OP.
 *
 * `authenticate()` has two phases, keyed off the request:
 *   1. No `code` on the query → it builds the authorize URL (response_type=code,
 *      PKCE challenge, state) and redirects the browser to Atlas.
 *   2. Atlas redirects back with `?code&state` → it checks `state`, exchanges the
 *      code at the token endpoint (sending the PKCE verifier), verifies the
 *      returned id_token against the instance JWKS, and hands the profile to the
 *      verify callback (or straight to `done` when there is none).
 *
 * Key verification reuses `@atlasauth/backend`'s {@link JwksCache} and `jose`, so
 * there is no second copy of the JWT/JWKS crypto here.
 *
 * ```ts
 * passport.use(new AtlasStrategy(
 *   { domain: 'id.atlasauth.net', clientID, clientSecret, callbackURL: 'https://app/cb' },
 *   (accessToken, refreshToken, profile, done) => done(null, { id: profile.id }),
 * ));
 * app.get('/auth/atlas', passport.authenticate('atlas'));
 * app.get('/auth/atlas/callback', passport.authenticate('atlas', { failureRedirect: '/login' }),
 *   (req, res) => res.redirect('/'));
 * ```
 */
export class AtlasStrategy extends PassportStrategy {
  readonly name = 'atlas';

  private readonly origin: string;
  private readonly issuer: string;
  private readonly authorizationURL: string;
  private readonly tokenURL: string;
  private readonly jwksURL: string;
  private readonly scope: string[];
  private readonly useState: boolean;
  private readonly usePkce: boolean;
  private readonly sessionKey: string;
  private readonly passReqToCallback: boolean;
  private readonly fetchImpl: typeof fetch;
  private readonly jwks: JwksCache;
  private readonly verify?: AtlasVerify | AtlasVerifyWithRequest;
  private readonly clientID: string;
  private readonly clientSecret?: string;
  private readonly callbackURL: string;

  constructor(options: AtlasStrategyOptions, verify?: AtlasVerify | AtlasVerifyWithRequest) {
    super();
    if (!options.domain) throw new Error('AtlasStrategy requires `domain`.');
    if (!options.clientID) throw new Error('AtlasStrategy requires `clientID`.');
    if (!options.callbackURL) throw new Error('AtlasStrategy requires `callbackURL`.');

    this.origin = normalizeOrigin(options.domain);
    this.issuer = options.issuer ?? this.origin;
    this.authorizationURL = options.authorizationURL ?? `${this.origin}/oauth2/authorize`;
    this.tokenURL = options.tokenURL ?? `${this.origin}/oauth2/token`;
    this.jwksURL = options.jwksURL ?? `${this.origin}/.well-known/jwks.json`;
    this.scope = normalizeScope(options.scope);
    this.useState = options.state ?? true;
    this.usePkce = options.pkce ?? true;
    this.sessionKey = options.sessionKey ?? `atlas:${new URL(this.origin).host}`;
    this.passReqToCallback = options.passReqToCallback ?? false;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.verify = verify;

    this.jwks = new JwksCache({ url: this.jwksURL, fetchImpl: this.fetchImpl, now: options.now });

    // Capture the rest for the exchange.
    this.clientID = options.clientID;
    this.clientSecret = options.clientSecret;
    this.callbackURL = options.callbackURL;
  }

  override authenticate(req: unknown, _options?: unknown): void {
    const request = req as { query?: Record<string, string | string[] | undefined> };
    const query = request.query ?? {};

    // The OP bounced an error back (consent denied, etc.) — surface it as a
    // failed authentication, not an internal error.
    const error = first(query.error);
    if (error) {
      this.fail({ message: first(query.error_description) ?? error }, 401);
      return;
    }

    const code = first(query.code);
    if (code) {
      void this.handleCallback(req, query, code);
    } else {
      void this.startAuthorization(req);
    }
  }

  /** Phase 1: build the authorize URL and redirect. */
  private async startAuthorization(req: unknown): Promise<void> {
    try {
      const tx: Transaction = {};
      const url = new URL(this.authorizationURL);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', this.clientID);
      url.searchParams.set('redirect_uri', this.callbackURL);
      url.searchParams.set('scope', this.scope.join(' '));

      if (this.useState) {
        tx.state = randomToken();
        url.searchParams.set('state', tx.state);
      }
      if (this.usePkce) {
        const pair = await createPkcePair();
        tx.codeVerifier = pair.verifier;
        url.searchParams.set('code_challenge', pair.challenge);
        url.searchParams.set('code_challenge_method', 'S256');
      }

      if (this.useState || this.usePkce) {
        const store = this.sessionStore(req);
        if (!store) {
          this.error(
            new Error(
              'AtlasStrategy needs a session to store the PKCE verifier / state. Mount session middleware before it, or disable with { state: false, pkce: false }.',
            ),
          );
          return;
        }
        store[this.sessionKey] = tx;
      }

      this.redirect(url.toString());
    } catch (err) {
      this.error(toError(err));
    }
  }

  /** Phase 2: validate state, exchange the code, verify the id_token. */
  private async handleCallback(
    req: unknown,
    query: Record<string, string | string[] | undefined>,
    code: string,
  ): Promise<void> {
    try {
      let verifier: string | undefined;

      if (this.useState || this.usePkce) {
        const store = this.sessionStore(req);
        const tx = store?.[this.sessionKey] as Transaction | undefined;
        // The transaction is single-use — clear it whatever happens next, so a
        // replayed callback finds nothing to validate against.
        if (store) delete store[this.sessionKey];

        if (this.useState) {
          const returned = first(query.state);
          if (!tx?.state || !returned || returned !== tx.state) {
            this.fail({ message: 'invalid_state' }, 403);
            return;
          }
        }
        if (this.usePkce) {
          verifier = tx?.codeVerifier;
          if (!verifier) {
            this.fail({ message: 'missing_pkce_verifier' }, 403);
            return;
          }
        }
      }

      const tokens = await this.exchange(code, verifier);
      if (!tokens || !tokens.id_token) {
        this.fail({ message: 'token_exchange_failed' }, 401);
        return;
      }

      const claims = await this.verifyIdToken(tokens.id_token);
      if (!claims) {
        this.fail({ message: 'invalid_id_token' }, 401);
        return;
      }

      const profile = profileFromClaims(claims);
      const accessToken = tokens.access_token ?? '';
      const refreshToken = tokens.refresh_token;

      if (!this.verify) {
        this.success(profile);
        return;
      }

      const done: VerifiedCallback = (err, user, info) => {
        if (err) return this.error(toError(err));
        if (!user) return this.fail(info ?? { message: 'rejected' }, 401);
        this.success(user, info);
      };

      if (this.passReqToCallback) {
        (this.verify as AtlasVerifyWithRequest)(req, accessToken, refreshToken, profile, done);
      } else {
        (this.verify as AtlasVerify)(accessToken, refreshToken, profile, done);
      }
    } catch (err) {
      this.error(toError(err));
    }
  }

  /** POST the authorization-code grant to the token endpoint. Returns null on failure. */
  private async exchange(code: string, codeVerifier?: string): Promise<TokenResponse | null> {
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.callbackURL,
      client_id: this.clientID,
    });
    if (codeVerifier) form.set('code_verifier', codeVerifier);
    if (this.clientSecret) form.set('client_secret', this.clientSecret);

    let res: Response;
    try {
      res = await this.fetchImpl(this.tokenURL, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: form.toString(),
      });
    } catch {
      return null;
    }
    if (!res.ok) return null;
    try {
      return (await res.json()) as TokenResponse;
    } catch {
      return null;
    }
  }

  /**
   * Verify the returned id_token: signature (RS256 or ES256) against the instance JWKS,
   * plus `iss` and `aud` (this client). Reuses the backend JWKS cache + `jose` —
   * the same verification the rest of the SDK does, not a second implementation.
   * Returns the claims, or null on any failure.
   */
  private async verifyIdToken(idToken: string): Promise<SessionClaims | null> {
    if (!idToken || idToken.split('.').length !== 3) return null;
    const keys = await this.jwks.get(readKid(idToken));
    if (!keys || keys.keys.length === 0) return null;
    try {
      const { payload } = await jwtVerify(idToken, createLocalJWKSet(keys as never), {
        // Atlas signs with RS256 (default) or ES256, chosen per instance.
        algorithms: ['RS256', 'ES256'],
        issuer: this.issuer,
        audience: this.clientID,
        clockTolerance: CLOCK_SKEW_SECONDS,
      });
      return payload as unknown as SessionClaims;
    } catch {
      return null;
    }
  }

  /** The `req.session` object, or null when no session middleware is mounted. */
  private sessionStore(req: unknown): Record<string, unknown> | null {
    const session = (req as { session?: Record<string, unknown> }).session;
    return session && typeof session === 'object' ? session : null;
  }
}

function normalizeScope(scope: string | string[] | undefined): string[] {
  if (Array.isArray(scope)) return scope.length ? [...scope] : ['openid', 'profile', 'email'];
  if (typeof scope === 'string' && scope.trim()) return scope.trim().split(/\s+/);
  return ['openid', 'profile', 'email'];
}

/** First value of a query param that may arrive as a string or an array. */
function first(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

/** A URL-safe random token for `state`, from Web Crypto (no `node:crypto`). */
function randomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
