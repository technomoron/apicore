import { afterEach, describe, expect, it, vi } from 'vitest';

import { MemoryRateLimitStore, RateLimitService, SecurityEventService } from '../../src/index';

const rule = { limit: 3, windowMs: 10_000 };

describe('Application quotas', () => {
	afterEach(() => vi.useRealTimers());

	it('counts weighted and rejected attempts without extending the window', async () => {
		vi.useFakeTimers();
		const store = new MemoryRateLimitStore();
		expect(await store.consume('ip', rule, 2)).toEqual({ allowed: true, limit: 3, remaining: 1, retryAfterSec: 0 });
		vi.advanceTimersByTime(2500);
		expect(await store.consume('ip', rule, 2)).toEqual({
			allowed: false,
			limit: 3,
			remaining: 0,
			retryAfterSec: 8
		});
		// Raising the test limit reveals that the rejected cost was counted.
		expect(await store.consume('ip', { ...rule, limit: 5 })).toMatchObject({ allowed: true, remaining: 0 });
		vi.advanceTimersByTime(7500);
		expect(await store.consume('ip', rule)).toMatchObject({ allowed: true, remaining: 2 });
	});

	it('evicts the oldest-used identity at the memory bound, including on denied attempts', async () => {
		const store = new MemoryRateLimitStore(2);
		const one = { ...rule, limit: 1 };
		await store.consume('a', one);
		await store.consume('b', one);
		expect((await store.consume('a', one)).allowed).toBe(false);
		await store.consume('c', one);
		expect((await store.consume('a', one)).allowed).toBe(false);
		expect((await store.consume('b', one)).allowed).toBe(true);
	});

	it('namespaces policies without collisions and supports custom async stores', async () => {
		const consume = vi.fn().mockResolvedValue({ allowed: true, limit: 3, remaining: 2, retryAfterSec: 0 });
		const service = new RateLimitService({
			policies: { 'a:b': { ...rule, identity: 'ip' }, a: { ...rule, identity: 'ip' } },
			store: { consume }
		});
		await service.consume('a:b', 'c', 2);
		await service.consume('a', 'b:c');
		expect(consume.mock.calls[0][0]).not.toBe(consume.mock.calls[1][0]);
		expect(consume.mock.calls[0]).toEqual([JSON.stringify(['a:b', 'c']), rule, 2]);
		consume.mockRejectedValueOnce(new Error('offline'));
		await expect(service.consume('a', 'ip')).rejects.toThrow('offline');
	});

	it('isolates real counters by policy and identity', async () => {
		const service = new RateLimitService({
			policies: { a: { ...rule, identity: 'ip' }, b: { ...rule, identity: 'ip' } }
		});
		await service.consume('a', 'one', 3);
		expect((await service.consume('a', 'one')).allowed).toBe(false);
		expect((await service.consume('b', 'one')).allowed).toBe(true);
		expect((await service.consume('a', 'two')).allowed).toBe(true);
	});

	it('consumes concurrent calls atomically in memory', async () => {
		const store = new MemoryRateLimitStore();
		const decisions = await Promise.all(Array.from({ length: 10 }, () => store.consume('same', rule)));
		expect(decisions.filter((decision) => decision.allowed)).toHaveLength(3);
	});

	it.each([0, -1, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1])(
		'rejects invalid numeric values: %s',
		async (value) => {
			expect(() => new MemoryRateLimitStore(value)).toThrow();
			const store = new MemoryRateLimitStore();
			await expect(store.consume('key', { ...rule, limit: value })).rejects.toThrow();
			await expect(store.consume('key', { ...rule, windowMs: value })).rejects.toThrow();
			await expect(store.consume('key', rule, value)).rejects.toThrow();
		}
	);

	it('rejects missing keys, unknown policies, and global user policies', async () => {
		await expect(new MemoryRateLimitStore().consume('', rule)).rejects.toThrow();
		const service = new RateLimitService({ policies: { ip: { ...rule, identity: 'ip' } } });
		await expect(service.consume('missing', 'ip')).rejects.toThrow('Unknown rate limit policy');
		await expect(service.consume('ip', '')).rejects.toThrow();
		expect(() => new RateLimitService({ global: 'missing' })).toThrow();
		expect(
			() => new RateLimitService({ global: 'user', policies: { user: { ...rule, identity: 'user' } } })
		).toThrow('must use IP');
	});
});

describe('SecurityEventService', () => {
	it('awaits the sink and prevents overriding the timestamp or event', async () => {
		const sink = vi.fn().mockResolvedValue(undefined);
		await new SecurityEventService(sink).report('auth.login.failed', {
			ip: '127.0.0.1',
			ts: 'fake',
			event: 'fake'
		});
		expect(sink).toHaveBeenCalledWith({
			ip: '127.0.0.1',
			ts: expect.stringMatching(/^\d{4}-/),
			event: 'auth.login.failed'
		});
	});

	it('does nothing without a sink and propagates sink failures', async () => {
		const consoleSpy = vi.spyOn(console, 'log');
		try {
			await new SecurityEventService().report('test');
			expect(consoleSpy).not.toHaveBeenCalled();
			await expect(
				new SecurityEventService(async () => {
					throw new Error('sink offline');
				}).report('test')
			).rejects.toThrow('sink offline');
		} finally {
			consoleSpy.mockRestore();
		}
	});
});
