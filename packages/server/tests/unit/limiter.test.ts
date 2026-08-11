import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ApiError } from '../../src/apicore-server';
import { createAuthRateLimitHook } from '../../src/limiter/auth-rate-limiter.js';
import { FixedWindowRateLimiter } from '../../src/limiter/fixed-window.js';

import type { ApiRequest } from '../../src/apicore-server';

const apiReqWithIp = (ip: string | null): ApiRequest => ({ getClientIp: () => ip }) as unknown as ApiRequest;

describe('FixedWindowRateLimiter', () => {
	it('allows requests up to max within a window', () => {
		const limiter = new FixedWindowRateLimiter();
		for (let i = 0; i < 3; i += 1) {
			expect(limiter.check('k', 3, 1000).allowed).toBe(true);
		}
	});

	it('denies the request that exceeds max', () => {
		const limiter = new FixedWindowRateLimiter();
		limiter.check('k', 2, 1000);
		limiter.check('k', 2, 1000);
		const decision = limiter.check('k', 2, 1000);
		expect(decision.allowed).toBe(false);
		expect(decision.retryAfterSec).toBeGreaterThan(0);
	});

	it('tracks keys independently', () => {
		const limiter = new FixedWindowRateLimiter();
		limiter.check('a', 1, 1000);
		expect(limiter.check('a', 1, 1000).allowed).toBe(false);
		expect(limiter.check('b', 1, 1000).allowed).toBe(true);
	});

	it('starts a fresh window once the previous one elapses', () => {
		vi.useFakeTimers();
		try {
			const limiter = new FixedWindowRateLimiter();
			expect(limiter.check('k', 1, 1000).allowed).toBe(true);
			expect(limiter.check('k', 1, 1000).allowed).toBe(false);

			vi.advanceTimersByTime(1000);
			expect(limiter.check('k', 1, 1000).allowed).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});

	it('reports retryAfterSec as the remaining window, rounded up', () => {
		vi.useFakeTimers();
		try {
			const limiter = new FixedWindowRateLimiter();
			limiter.check('k', 1, 10_000);
			vi.advanceTimersByTime(2500);
			const decision = limiter.check('k', 1, 10_000);
			expect(decision.allowed).toBe(false);
			// 7.5s remaining rounds up to 8.
			expect(decision.retryAfterSec).toBe(8);
		} finally {
			vi.useRealTimers();
		}
	});

	it('treats non-positive max or window as unlimited', () => {
		const limiter = new FixedWindowRateLimiter();
		expect(limiter.check('k', 0, 1000).allowed).toBe(true);
		expect(limiter.check('k', 5, 0).allowed).toBe(true);
		expect(limiter.check('', 1, 1000).allowed).toBe(true);
	});

	it('prunes least-recently-used keys beyond the cap', () => {
		const limiter = new FixedWindowRateLimiter(2);
		limiter.check('a', 1, 60_000);
		limiter.check('b', 1, 60_000);
		// 'a' is evicted when 'c' arrives, so its counter resets.
		limiter.check('c', 1, 60_000);
		expect(limiter.check('a', 1, 60_000).allowed).toBe(true);
		// 'c' was inserted most recently and retains its count.
		expect(limiter.check('c', 1, 60_000).allowed).toBe(false);
	});

	it('keeps active keys alive by refreshing insertion order', () => {
		const limiter = new FixedWindowRateLimiter(2);
		limiter.check('a', 5, 60_000);
		limiter.check('b', 5, 60_000);
		// Touch 'a' so it moves to the end of the eviction order.
		limiter.check('a', 5, 60_000);
		limiter.check('c', 5, 60_000);
		// 'b' should have been evicted rather than 'a'.
		expect(limiter.check('a', 5, 60_000).allowed).toBe(true);
	});
});

describe('createAuthRateLimitHook', () => {
	let warnSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
	});

	afterEach(() => {
		warnSpy.mockRestore();
	});

	it('is a no-op when no endpoints are configured', () => {
		const hook = createAuthRateLimitHook({});
		expect(() => hook({ apiReq: apiReqWithIp('1.1.1.1'), endpoint: 'login' })).not.toThrow();
	});

	it('throws ApiError 429 once the endpoint limit is exceeded', () => {
		const hook = createAuthRateLimitHook({ login: { max: 2, windowSec: 60 } });
		const apiReq = apiReqWithIp('1.1.1.1');

		hook({ apiReq, endpoint: 'login' });
		hook({ apiReq, endpoint: 'login' });

		try {
			hook({ apiReq, endpoint: 'login' });
			throw new Error('expected a 429');
		} catch (error) {
			expect(error).toBeInstanceOf(ApiError);
			const apiError = error as ApiError;
			expect(apiError.code).toBe(429);
			expect(apiError.message).toContain('Too many requests');
			expect((apiError.data as { retryAfterSec: number }).retryAfterSec).toBeGreaterThan(0);
		}
	});

	it('limits each endpoint separately', () => {
		const hook = createAuthRateLimitHook({
			login: { max: 1, windowSec: 60 },
			'oauth-token': { max: 1, windowSec: 60 }
		});
		const apiReq = apiReqWithIp('1.1.1.1');

		hook({ apiReq, endpoint: 'login' });
		hook({ apiReq, endpoint: 'oauth-token' });

		expect(() => hook({ apiReq, endpoint: 'login' })).toThrow(ApiError);
		expect(() => hook({ apiReq, endpoint: 'oauth-token' })).toThrow(ApiError);
	});

	it('limits each client IP separately', () => {
		const hook = createAuthRateLimitHook({ login: { max: 1, windowSec: 60 } });

		hook({ apiReq: apiReqWithIp('1.1.1.1'), endpoint: 'login' });
		expect(() => hook({ apiReq: apiReqWithIp('1.1.1.1'), endpoint: 'login' })).toThrow(ApiError);
		expect(() => hook({ apiReq: apiReqWithIp('2.2.2.2'), endpoint: 'login' })).not.toThrow();
	});

	it('buckets unresolved client IPs together under a single key', () => {
		const hook = createAuthRateLimitHook({ login: { max: 1, windowSec: 60 } });

		hook({ apiReq: apiReqWithIp(null), endpoint: 'login' });
		expect(() => hook({ apiReq: apiReqWithIp(null), endpoint: 'login' })).toThrow(ApiError);
	});

	it('ignores endpoints that are not configured', () => {
		const hook = createAuthRateLimitHook({ login: { max: 1, windowSec: 60 } });
		const apiReq = apiReqWithIp('1.1.1.1');

		hook({ apiReq, endpoint: 'passkey-challenge' });
		expect(() => hook({ apiReq, endpoint: 'passkey-challenge' })).not.toThrow();
	});

	it('treats a non-positive max or window as disabled', () => {
		const apiReq = apiReqWithIp('1.1.1.1');
		const zeroMax = createAuthRateLimitHook({ login: { max: 0, windowSec: 60 } });
		const zeroWindow = createAuthRateLimitHook({ login: { max: 5, windowSec: 0 } });

		for (let i = 0; i < 3; i += 1) {
			expect(() => zeroMax({ apiReq, endpoint: 'login' })).not.toThrow();
			expect(() => zeroWindow({ apiReq, endpoint: 'login' })).not.toThrow();
		}
	});

	it('shares an injected limiter instance across hooks', () => {
		const shared = new FixedWindowRateLimiter();
		const first = createAuthRateLimitHook({ login: { max: 1, windowSec: 60 } }, shared);
		const second = createAuthRateLimitHook({ login: { max: 1, windowSec: 60 } }, shared);
		const apiReq = apiReqWithIp('1.1.1.1');

		first({ apiReq, endpoint: 'login' });
		expect(() => second({ apiReq, endpoint: 'login' })).toThrow(ApiError);
	});
});
