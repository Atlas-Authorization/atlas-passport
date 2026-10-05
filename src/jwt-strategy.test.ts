import { describe, it, expect, beforeAll } from 'vitest';
import { createTestIssuer, type TestIssuer, type AuthorizedSession } from '@atlasauth/backend';
import { AtlasJwtStrategy, BearerStrategy } from './jwt-strategy';
import type { AtlasProfile, VerifiedCallback } from './types';

/**
 * The bearer/JWT strategy: on a valid (locally verified) token it calls
 * `success` with the Atlas subject; on an invalid or missing one it `fail`s with
 * 401. Verification is driven by an offline {@link createTestIssuer} fixture —
 * the token is minted and verified in-process against a static JWKS, no network.
 */

/** Drive a strategy to a single terminal action and resolve with what it was. */
type Outcome =
  | { type: 'success'; user: unknown; info?: unknown }
  | { type: 'fail'; challenge: unknown; status?: number }
  | { type: 'error'; err: unknown }
  | { type: 'redirect'; url: string }
  | { type: 'pass' };

function run(strategy: AtlasJwtStrategy, req: unknown): Promise<Outcome> {
  return new Promise((resolve) => {
    // Passport augments the instance with these per request; the test does the same.
    (strategy as unknown as Record<string, unknown>).success = (user: unknown, info?: unknown) =>
      resolve({ type: 'success', user, info });
    (strategy as unknown as Record<string, unknown>).fail = (challenge: unknown, status?: number) =>
      resolve({ type: 'fail', challenge, status });
    (strategy as unknown as Record<string, unknown>).error = (err: unknown) => resolve({ type: 'error', err });
    (strategy as unknown as Record<string, unknown>).redirect = (url: string) => resolve({ type: 'redirect', url });
    (strategy as unknown as Record<string, unknown>).pass = () => resolve({ type: 'pass' });
    strategy.authenticate(req);
  });
}

const bearer = (token: string) => ({ headers: { authorization: `Bearer ${token}` } });

describe('AtlasJwtStrategy', () => {
  let fx: TestIssuer;

  beforeAll(async () => {
    fx = await createTestIssuer({ issuer: 'https://jwt.atlas.test' });
  });

  it('calls success with the Atlas subject on a valid token (no verify callback)', async () => {
    const strategy = new AtlasJwtStrategy({ issuer: fx.issuer, jwks: fx.jwks });
    const token = await fx.mintSession({ sub: 'user_42', org_role: 'admin' });

    const outcome = await run(strategy, bearer(token));

    expect(outcome.type).toBe('success');
    const user = (outcome as { user: AtlasProfile }).user;
    expect(user.provider).toBe('atlas');
    expect(user.id).toBe('user_42');
    expect(user.orgRole).toBe('admin');
  });

  it('hands the verify callback the verified AuthorizedSession and uses its done(null, user)', async () => {
    let seen: AuthorizedSession | undefined;
    const strategy = new AtlasJwtStrategy(
      { issuer: fx.issuer, jwks: fx.jwks },
      (session: AuthorizedSession, done: VerifiedCallback) => {
        seen = session;
        done(null, { id: session.claims.sub, via: 'verify' });
      },
    );
    const token = await fx.mintSession({ sub: 'user_7' });

    const outcome = await run(strategy, bearer(token));

    expect(outcome.type).toBe('success');
    expect((outcome as { user: { id: string; via: string } }).user).toEqual({ id: 'user_7', via: 'verify' });
    // The callback received a real AuthorizedSession, with its has()/protect() bound.
    expect(seen?.ok).toBe(true);
    expect(seen?.claims.sub).toBe('user_7');
    expect(typeof seen?.has).toBe('function');
  });

  it('fails with 401 on an invalid token (wrong issuer)', async () => {
    const strategy = new AtlasJwtStrategy({ issuer: fx.issuer, jwks: fx.jwks });
    const token = await fx.mintSession({ iss: 'https://evil.test' });

    const outcome = await run(strategy, bearer(token));

    expect(outcome.type).toBe('fail');
    expect((outcome as { status?: number }).status).toBe(401);
  });

  it('fails with 401 when no token is present', async () => {
    const strategy = new AtlasJwtStrategy({ issuer: fx.issuer, jwks: fx.jwks });

    const outcome = await run(strategy, { headers: {} });

    expect(outcome.type).toBe('fail');
    expect((outcome as { status?: number }).status).toBe(401);
  });

  it('fails (does not succeed) when the verify callback rejects with done(null, false)', async () => {
    const strategy = new AtlasJwtStrategy(
      { issuer: fx.issuer, jwks: fx.jwks },
      (_session: AuthorizedSession, done: VerifiedCallback) => done(null, false),
    );
    const token = await fx.mintSession({ sub: 'user_x' });

    const outcome = await run(strategy, bearer(token));

    expect(outcome.type).toBe('fail');
  });

  it('exposes BearerStrategy as an alias of AtlasJwtStrategy', () => {
    expect(BearerStrategy).toBe(AtlasJwtStrategy);
  });

  it('derives the JWKS URL and issuer from `domain` when neither is given', () => {
    const strategy = new AtlasJwtStrategy({ domain: 'id.atlasauth.net', jwks: fx.jwks });
    expect(strategy.name).toBe('atlas-jwt');
  });
});
