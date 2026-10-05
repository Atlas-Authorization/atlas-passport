# @atlasauth/passport

[Passport.js](https://www.passportjs.org/) strategies for [Atlas](https://atlasauth.net).

Two strategies, both wrapping [`@atlasauth/backend`](../backend) so there is a
single verifier and a single JWKS cache behind your whole app:

- **`AtlasStrategy`** — the interactive OIDC **authorization-code** flow (with
  PKCE) against the Atlas OP, for "Sign in with Atlas" browser login.
- **`AtlasJwtStrategy`** (alias **`BearerStrategy`**) — verifies an Atlas
  access/session token on an API route. Verification is **local** — the JWT is
  checked against the instance's cached JWKS with no network call on the hot path
  (§7.3), the same guarantee `@atlasauth/express` and `@atlasauth/nextjs` give.

```bash
npm install @atlasauth/passport passport
```

## Bearer / JWT — protect an API

```ts
import passport from 'passport';
import express from 'express';
import { AtlasJwtStrategy, type AtlasProfile } from '@atlasauth/passport';

passport.use(
  new AtlasJwtStrategy({
    domain: 'id.atlasauth.net', // derives issuer + {domain}/.well-known/jwks.json
    // or spell them out: issuer, jwksUrl / jwks, authorizedParties, audience
  }),
);

const app = express();
app.use(passport.initialize());

// These are stateless API credentials — no login session to persist.
const requireAtlas = passport.authenticate('atlas-jwt', { session: false });

app.get('/api/me', requireAtlas, (req, res) => {
  const user = req.user as AtlasProfile;
  res.json({ userId: user.id, orgRole: user.orgRole });
});
```

Reads `Authorization: Bearer <jwt>` or, failing that, the `__session` cookie
(header first). A missing/invalid token fails with `401`. Pass a verify callback
to authorize inline — it receives the verified `AuthorizedSession`, with the
`has()` / `protect()` helpers bound to the claims:

```ts
passport.use(
  new AtlasJwtStrategy({ domain: 'id.atlasauth.net' }, (session, done) => {
    if (!session.has({ permission: 'billing:read' })) return done(null, false);
    done(null, { id: session.claims.sub });
  }),
);
```

## Authorization code — "Sign in with Atlas"

```ts
import passport from 'passport';
import session from 'express-session';
import express from 'express';
import { AtlasStrategy } from '@atlasauth/passport';

passport.use(
  new AtlasStrategy(
    {
      domain: 'id.atlasauth.net',
      clientID: process.env.ATLAS_CLIENT_ID!,
      clientSecret: process.env.ATLAS_CLIENT_SECRET, // omit for a public client (PKCE only)
      callbackURL: 'https://app.example.com/auth/atlas/callback',
      scope: ['openid', 'profile', 'email'], // the default
    },
    (accessToken, refreshToken, profile, done) => {
      // Find-or-create your own user from the verified profile, then:
      done(null, { id: profile.id, email: profile.emails?.[0]?.value });
    },
  ),
);

const app = express();
// A session is required: the PKCE verifier + `state` are stashed there between
// the redirect and the callback.
app.use(session({ secret: process.env.SESSION_SECRET!, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user as Express.User));

// 1) Kick off login — redirects to Atlas.
app.get('/auth/atlas', passport.authenticate('atlas'));

// 2) Atlas redirects back here with ?code&state.
app.get(
  '/auth/atlas/callback',
  passport.authenticate('atlas', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/'),
);
```

`authenticate()` has two phases keyed off the request: no `code` on the query →
it builds the authorize URL (PKCE `S256` challenge + `state`) and redirects; a
`?code&state` callback → it checks `state`, exchanges the code at the token
endpoint (sending the PKCE verifier), verifies the returned **id_token** against
the instance JWKS (`iss` + `aud`), and hands the profile to your verify callback.

## Options

### `AtlasStrategy`

| option | type | notes |
| --- | --- | --- |
| `domain` | `string` | **required** — the Atlas origin (`id.atlasauth.net` or a full URL). |
| `clientID` | `string` | **required** — the registered OIDC client id. |
| `clientSecret` | `string?` | omit for a public client; PKCE proves the exchange. |
| `publishableKey` | `string?` | the instance `pk_…` (informational). |
| `callbackURL` | `string` | **required** — the registered redirect URI. |
| `scope` | `string \| string[]?` | default `['openid','profile','email']`. |
| `issuer` | `string?` | expected id_token `iss`; defaults to `domain`. |
| `authorizationURL` / `tokenURL` / `jwksURL` | `string?` | endpoint overrides. |
| `state` / `pkce` | `boolean?` | default `true` (both need a session). |
| `passReqToCallback` | `boolean?` | pass `req` as the verify callback's first arg. |

### `AtlasJwtStrategy` / `BearerStrategy`

| option | type | notes |
| --- | --- | --- |
| `domain` | `string?` | derives `issuer` + `{domain}/.well-known/jwks.json`. |
| `issuer` | `string?` | expected `iss` (required if no `domain`). |
| `jwksUrl` / `jwks` | `string?` / `Jwks?` | key source; `jwks` is a static set for offline verify. |
| `authorizedParties` | `readonly string[]?` | §7.3 azp allowlist. |
| `audience` | `string \| readonly string[]?` | §S4 expected audience (opt-in). |
| `backend` | `AtlasBackend?` | reuse a pre-built verifier (shared JWKS cache). |
| `passReqToCallback` | `boolean?` | pass `req` to the verify callback. |

## Testing

```bash
pnpm -F @atlasauth/passport test
```

The suite runs fully offline: tokens are minted and verified against an ephemeral
JWKS via `@atlasauth/backend`'s `createTestIssuer()`, and the authorization-code
exchange runs against a mocked `fetch`.

## License

MIT
