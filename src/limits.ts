/**
 * Rate limiting and grant-usage gates for this adapter. Both wrap the framework-neutral checks from
 * `@atlasauth/backend` (`rateLimitRequest`, `requireGrantUsage`) and accept either the limiter /
 * usage options or an already-built check. A limit store or usage call that throws is an error, never an allow.
 */
import { rateLimitRequest, requireGrantUsage } from '@atlasauth/backend';

/** Options for the usage gate (`requireGrantUsage` in `@atlasauth/backend`). */
export type GrantUsageOptions = Parameters<typeof requireGrantUsage>[0];
/** The framework-neutral usage check `requireGrantUsage(opts)` returns. */
export type GrantUsageCheck = ReturnType<typeof requireGrantUsage>;
/** A limiter from `createRateLimiter` in `@atlasauth/backend`. */
export type RateLimiter = Parameters<typeof rateLimitRequest>[0];
/** Picks the rate-limit subject (key, user, org, machine, ip) out of a request. */
export type RateLimitSubjectFrom = Parameters<typeof rateLimitRequest>[1];
/** The framework-neutral rate-limit check `rateLimitRequest(limiter, subjectFrom)` returns. */
export type RateLimitCheck = ReturnType<typeof rateLimitRequest>;

/** Verified claims (a session or a machine/agent access token), or nothing when signed out. */
export type LimitClaims = object | null | undefined;
/** The headers a limit decision adds to the response (`RateLimit-*`, `Retry-After`). */
export type LimitHeaders = Record<string, string>;
/** What a limit gate decided. A denial carries the status (429 or 403) and body to send. */
export type LimitVerdict =
  | { allowed: true; headers?: LimitHeaders }
  | { allowed: false; status: number; headers?: LimitHeaders; body?: unknown };
/** What a gate reads from a request. `ip` is only used for the default rate-limit subject. */
export interface LimitInput {
  claims: LimitClaims;
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
}
/** One request-level gate: the shared shape every adapter wraps in its own idiom. */
export type LimitGate = (input: LimitInput) => Promise<LimitVerdict>;

/** Lower-case the header names and join repeated values, the shape both neutral checks expect. */
export function flattenHeaders(headers: LimitInput['headers']): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    out[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
  }
  return out;
}

/**
 * The client address from `x-forwarded-for`. Only trust it behind a proxy that sets the header;
 * pass your own `ip` (or a `subjectFrom`) otherwise.
 */
export function forwardedIp(headers: Record<string, string>): string | undefined {
  return headers['x-forwarded-for']?.split(',')[0]?.trim() || headers['x-real-ip'] || undefined;
}

/** Default subject: the signed-in user, their active org, a machine id claim, and the address. */
function defaultSubject(req: { claims?: Record<string, unknown> | null; ip?: string }) {
  const c = req.claims ?? {};
  const str = (v: unknown) => (typeof v === 'string' && v ? v : undefined);
  return { userId: str(c.sub), orgId: str(c.org_id), machineId: str(c.machine_id), ip: req.ip };
}

function neutral(input: LimitInput) {
  return { claims: input.claims, headers: flattenHeaders(input.headers), ip: input.ip } as never;
}

/**
 * Turn a limiter (or an already-built `rateLimitRequest` check) into a gate.
 * Without `subjectFrom` the subject is the user, org, machine and address of the request.
 */
export function rateLimitGate(limiter: RateLimiter | RateLimitCheck, subjectFrom?: RateLimitSubjectFrom): LimitGate {
  const check = (
    typeof limiter === 'function' ? limiter : rateLimitRequest(limiter, subjectFrom ?? (defaultSubject as unknown as RateLimitSubjectFrom))
  ) as (req: never) => Promise<LimitVerdict>;
  return (input) => check(neutral(input));
}

/** Turn usage-gate options (or an already-built `requireGrantUsage` check) into a gate. */
export function grantUsageGate(options: GrantUsageOptions | GrantUsageCheck): LimitGate {
  const check = (typeof options === 'function' ? options : requireGrantUsage(options)) as (req: never) => Promise<LimitVerdict>;
  return (input) => check(neutral(input));
}

/** The JSON body of a denial. */
export function denialBody(v: Extract<LimitVerdict, { allowed: false }>): unknown {
  return v.body ?? { errors: [{ code: v.status === 429 ? 'RATE_LIMITED' : 'FORBIDDEN' }] };
}

/** A fetch `Response` for a denial, for the adapters on the Web platform. */
export function denialResponse(v: Extract<LimitVerdict, { allowed: false }>): Response {
  return new Response(JSON.stringify(denialBody(v)), {
    status: v.status,
    headers: { 'content-type': 'application/json', ...(v.headers ?? {}) },
  });
}

/** Copy a Web `Headers` into the plain record the gates read. */
export function webHeaders(headers: { forEach(cb: (value: string, key: string) => void): void }): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key] = value;
  });
  return out;
}

/** Add the allow-path headers to a Web `Response`, ignoring one whose headers are frozen. */
export function withVerdictHeaders(response: Response, headers?: LimitHeaders): Response {
  if (!headers) return response;
  try {
    for (const [k, v] of Object.entries(headers)) response.headers.set(k, v);
    return response;
  } catch {
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: mergeHeaders(response.headers, headers) });
  }
}

/** Options shared by every adapter wrapper. */
export interface LimitWrapOptions<Ctx> {
  /** Where the verified claims live on this framework's request. A sensible default is used where one exists. */
  claims?: (ctx: Ctx) => LimitClaims | Promise<LimitClaims>;
}

// ── Passport (Express-style middleware, structural types) ────────────────────
/** The slice of an Express request the limit middleware reads. */
export interface PassportLimitRequest {
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
  /** Set by `passport.authenticate('atlas-jwt')`: an `AtlasProfile`, whose `claims` the limits read. */
  user?: { claims?: object | null } | null;
}
/** The slice of an Express response the limit middleware writes. */
export interface PassportLimitResponse {
  set(headers: Record<string, string>): unknown;
  status(code: number): { json(body: unknown): unknown };
}

/** Options for the passport limit middleware. */
export interface AtlasLimitOptions extends LimitWrapOptions<PassportLimitRequest> {
  /** Rate limit only: pick the subject yourself instead of user/org/machine/address. */
  subjectFrom?: RateLimitSubjectFrom;
}

function middleware(gate: LimitGate, options: AtlasLimitOptions) {
  return async (req: PassportLimitRequest, res: PassportLimitResponse, next: (err?: unknown) => void): Promise<void> => {
    try {
      const claims = options.claims ? await options.claims(req) : req.user?.claims;
      const verdict = await gate({ claims, headers: req.headers, ip: req.ip });
      if (verdict.headers) res.set(verdict.headers);
      if (!verdict.allowed) {
        res.status(verdict.status).json(denialBody(verdict));
        return;
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/** Rate limit after `passport.authenticate(...)`: 429 with `Retry-After` and `RateLimit-*` headers when over. */
export function atlasRateLimit(limiter: RateLimiter | RateLimitCheck, options: AtlasLimitOptions = {}) {
  return middleware(rateLimitGate(limiter, options.subjectFrom), options);
}

/** Consume a grant counter after `passport.authenticate(...)`: 429 when spent, 403 when the grant is missing or expired. */
export function atlasGrantUsage(usage: GrantUsageOptions | GrantUsageCheck, options: AtlasLimitOptions = {}) {
  return middleware(grantUsageGate(usage), options);
}

function mergeHeaders(base: Headers, extra: LimitHeaders): Headers {
  const h = new Headers(base);
  for (const [k, v] of Object.entries(extra)) h.set(k, v);
  return h;
}
