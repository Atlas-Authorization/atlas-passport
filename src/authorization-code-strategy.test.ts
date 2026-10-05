import { describe, it, expect, beforeAll } from 'vitest';
import { SignJWT } from 'jose';
import { createTestIssuer, type TestIssuer } from '@atlasauth/backend';
import { AtlasStrategy } from './authorization-code-strategy';
import type { AtlasProfile, VerifiedCallback } from './types';

/**
 * The OIDC authorization-code strategy. Two behaviours proven here:
 *   - the "start" phase builds the right authorize URL (PKCE challenge + state)
 *     and stashes the transaction in the session;
 *   - the "callback" phase checks state, exchanges the code (mocked `fetch`),
 *     verifies the returned id_token against the fixture JWKS, and succeeds with
 *     the profile.
 */

type Outcome =
  | { type: 'success'; user: unknown; info?: unknown }
  | { type: 'fail'; challenge: unknown; status?: number }
  | { type: 'error'; err: unknown }
  | { type: 'redirect'; url: string }
  | { type: 'pass' };

function run(strategy: AtlasStrategy, req: unknown): Promise<Outcome> {
  return new Promise((resolve) => {
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

const DOMAIN = 'id.atlasauth.test';
const ISSUER = 'https://id.atlasauth.test';
const CLIENT_ID = 'client_abc';
const CALLBACK = 'https://app.example.test/auth/atlas/callback';

describe('AtlasStrategy (authorization-code + PKCE)', () => {
  let fx: TestIssuer;

  beforeAll(async () => {
    fx = await createTestIssuer({ issuer: ISSUER });
  });

  /** Mint an OIDC id_token signed by the fixture key, with aud = our client. */
  async function mintIdToken(claims: Record<string, unknown> = {}): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      iss: ISSUER,
      aud: CLIENT_ID,
      sub: 'user_oidc',
      name: 'Ada Lovelace',
      email: 'ada@example.test',
      email_verified: true,
      iat: now,
      exp: now + 300,
      ...claims,
    })
      .setProtectedHeader({ alg: 'RS256', kid: fx.kid })
      .sign(fx.privateKey);
  }

  it('builds the authorize URL with PKCE + state and stashes the transaction', async () => {
    const strategy = new AtlasStrategy({ domain: DOMAIN, clientID: CLIENT_ID, callbackURL: CALLBACK });
    const session: Record<string, unknown> = {};

    const outcome = await run(strategy, { query: {}, session });

    expect(outcome.type).toBe('redirect');
    const url = new URL((outcome as { url: string }).url);
    expect(url.origin + url.pathname).toBe(`${ISSUER}/oauth2/authorize`);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(url.searchParams.get('redirect_uri')).toBe(CALLBACK);
    expect(url.searchParams.get('scope')).toBe('openid profile email');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toBeTruthy();
    const state = url.searchParams.get('state');
    expect(state).toBeTruthy();

    // The transaction (state + verifier) was stored for the callback to validate.
    const tx = session[`atlas:${DOMAIN}`] as { state?: string; codeVerifier?: string };
    expect(tx.state).toBe(state);
    expect(tx.codeVerifier).toBeTruthy();
  });

  it('errors when state/PKCE are on but no session is mounted', async () => {
    const strategy = new AtlasStrategy({ domain: DOMAIN, clientID: CLIENT_ID, callbackURL: CALLBACK });
    const outcome = await run(strategy, { query: {} });
    expect(outcome.type).toBe('error');
    expect(String((outcome as { err: Error }).err.message)).toContain('session');
  });

  it('exchanges the code and succeeds with the verified profile', async () => {
    const idToken = await mintIdToken({ sub: 'user_oidc' });
    let exchangeBody = '';

    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const u = String(input);
      if (u.endsWith('/oauth2/token')) {
        exchangeBody = String(init?.body ?? '');
        return new Response(
          JSON.stringify({ access_token: 'at_1', refresh_token: 'rt_1', id_token: idToken, token_type: 'Bearer' }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (u.includes('/.well-known/jwks.json')) {
        return new Response(JSON.stringify(fx.jwks), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      throw new Error(`unexpected fetch: ${u}`);
    }) as typeof fetch;

    const strategy = new AtlasStrategy(
      { domain: DOMAIN, clientID: CLIENT_ID, clientSecret: 'sek_1', callbackURL: CALLBACK, fetchImpl },
      (accessToken: string, refreshToken: string | undefined, profile: AtlasProfile, done: VerifiedCallback) => {
        done(null, { id: profile.id, accessToken, refreshToken, email: profile.emails?.[0]?.value });
      },
    );

    // 1) start → capture the state + verifier the strategy stored.
    const session: Record<string, unknown> = {};
    await run(strategy, { query: {}, session });
    const tx = session[`atlas:${DOMAIN}`] as { state: string; codeVerifier: string };

    // 2) callback with the matching state and an authorization code.
    const outcome = await run(strategy, { query: { code: 'auth_code_1', state: tx.state }, session });

    expect(outcome.type).toBe('success');
    const user = (outcome as { user: Record<string, unknown> }).user;
    expect(user.id).toBe('user_oidc');
    expect(user.accessToken).toBe('at_1');
    expect(user.refreshToken).toBe('rt_1');
    expect(user.email).toBe('ada@example.test');

    // The exchange sent the authorization-code grant WITH the PKCE verifier.
    const body = new URLSearchParams(exchangeBody);
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code')).toBe('auth_code_1');
    expect(body.get('client_id')).toBe(CLIENT_ID);
    expect(body.get('code_verifier')).toBe(tx.codeVerifier);
    expect(body.get('client_secret')).toBe('sek_1');

    // The transaction was consumed (single-use).
    expect(session[`atlas:${DOMAIN}`]).toBeUndefined();
  });

  it('rejects a callback whose state does not match (CSRF guard)', async () => {
    const strategy = new AtlasStrategy({ domain: DOMAIN, clientID: CLIENT_ID, callbackURL: CALLBACK });
    const session: Record<string, unknown> = {};
    await run(strategy, { query: {}, session });

    const outcome = await run(strategy, { query: { code: 'c', state: 'not-the-stored-state' }, session });
    expect(outcome.type).toBe('fail');
    expect((outcome as { status?: number }).status).toBe(403);
  });

  it('surfaces an OP error redirect as a failed authentication', async () => {
    const strategy = new AtlasStrategy({ domain: DOMAIN, clientID: CLIENT_ID, callbackURL: CALLBACK });
    const outcome = await run(strategy, {
      query: { error: 'access_denied', error_description: 'user said no' },
      session: {},
    });
    expect(outcome.type).toBe('fail');
    expect((outcome as { challenge: { message: string } }).challenge.message).toBe('user said no');
  });

  it('fails when the id_token fails verification (wrong audience)', async () => {
    const idToken = await mintIdToken({ aud: 'some_other_client' });
    const fetchImpl = (async (input: RequestInfo | URL) => {
      const u = String(input);
      if (u.endsWith('/oauth2/token')) {
        return new Response(JSON.stringify({ access_token: 'at', id_token: idToken }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(JSON.stringify(fx.jwks), { status: 200, headers: { 'content-type': 'application/json' } });
    }) as typeof fetch;

    const strategy = new AtlasStrategy({ domain: DOMAIN, clientID: CLIENT_ID, callbackURL: CALLBACK, fetchImpl });
    const session: Record<string, unknown> = {};
    await run(strategy, { query: {}, session });
    const tx = session[`atlas:${DOMAIN}`] as { state: string };

    const outcome = await run(strategy, { query: { code: 'c', state: tx.state }, session });
    expect(outcome.type).toBe('fail');
    expect((outcome as { challenge: { message: string } }).challenge.message).toBe('invalid_id_token');
  });

  it('reports a failed token exchange as a 401 fail', async () => {
    const fetchImpl = (async (input: RequestInfo | URL) => {
      const u = String(input);
      if (u.endsWith('/oauth2/token')) return new Response('nope', { status: 400 });
      return new Response(JSON.stringify(fx.jwks), { status: 200, headers: { 'content-type': 'application/json' } });
    }) as typeof fetch;

    const strategy = new AtlasStrategy({ domain: DOMAIN, clientID: CLIENT_ID, callbackURL: CALLBACK, fetchImpl });
    const session: Record<string, unknown> = {};
    await run(strategy, { query: {}, session });
    const tx = session[`atlas:${DOMAIN}`] as { state: string };

    const outcome = await run(strategy, { query: { code: 'c', state: tx.state }, session });
    expect(outcome.type).toBe('fail');
    expect((outcome as { challenge: { message: string } }).challenge.message).toBe('token_exchange_failed');
  });

  const profileShape: AtlasProfile = { provider: 'atlas', id: 'x', claims: { iss: '', sub: 'x', sid: '', exp: 0 } };
  it('type: AtlasProfile shape is exported', () => {
    expect(profileShape.provider).toBe('atlas');
  });
});
