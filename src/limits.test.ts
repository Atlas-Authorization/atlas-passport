import { describe, expect, it, vi } from 'vitest';
import { atlasGrantUsage, atlasRateLimit } from './limits';

const allow = vi.fn(async (_req: unknown) => ({ allowed: true as const, headers: { 'RateLimit-Remaining': '4' } }));
const deny = async () => ({ allowed: false as const, status: 429, body: { error: 'slow' } });
const res = () => {
  const r = { headers: {} as Record<string, string>, code: 0, body: undefined as unknown, set: (h: Record<string, string>) => Object.assign(r.headers, h), status: (c: number) => ({ json: (b: unknown) => ((r.code = c), (r.body = b)) }) };
  return r;
};

describe('passport limits', () => {
  it('reads claims from req.user and continues', async () => {
    const r = res();
    const next = vi.fn();
    await atlasRateLimit(allow as never)({ headers: { a: 'b' }, ip: '1.1.1.1', user: { claims: { sub: 'u' } } }, r, next);
    expect(next).toHaveBeenCalledWith();
    expect(r.headers).toEqual({ 'RateLimit-Remaining': '4' });
    expect(allow).toHaveBeenLastCalledWith({ claims: { sub: 'u' }, headers: { a: 'b' }, ip: '1.1.1.1' });
  });

  it('answers a denial', async () => {
    const r = res();
    const next = vi.fn();
    await atlasGrantUsage(deny as never)({ headers: {} }, r, next);
    expect(next).not.toHaveBeenCalled();
    expect(r.code).toBe(429);
    expect(r.body).toEqual({ error: 'slow' });
  });
});
