import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import type { TokenStore } from '../../../src/token/base.js';
import type { Token } from '../../../src/token/types.js';

type StoreFactoryResult = {
	store: TokenStore;
	cleanup?: () => Promise<void> | void;
};

function baseToken(overrides: Partial<Token> = {}): Token {
	return {
		accessToken: overrides.accessToken ?? 'access-1',
		refreshToken: overrides.refreshToken ?? 'refresh-1',
		...overrides,
		userId: overrides.userId !== undefined ? String(overrides.userId) : '1'
	};
}

function expectDatesClose(a: Date, b: Date, toleranceMs = 200) {
	expect(Math.abs(a.getTime() - b.getTime())).toBeLessThan(toleranceMs);
}

export function runTokenStoreSuite(
	name: string,
	factory: () => Promise<StoreFactoryResult> | StoreFactoryResult
): void {
	describe(name, () => {
		let store!: TokenStore;
		let cleanup: StoreFactoryResult['cleanup'];
		let testUserId = 1;

		beforeEach(async () => {
			const created = await factory();
			store = created.store;
			cleanup = created.cleanup;
			testUserId += 1; // isolate uniqueness per test
		});

		afterEach(async () => {
			await store?.close();
			if (cleanup) {
				await cleanup();
			}
		});

		it('saves and fetches tokens with defaults normalized', async () => {
			const before = Date.now();

			await store.save(baseToken());
			const fetched = await store.get({ refreshToken: 'refresh-1' });

			expect(fetched).not.toBeNull();
			expect(typeof fetched?.sessionId).toBe('string');
			expect(fetched?.sessionId?.length).toBeGreaterThan(0);
			expect(fetched?.domain).toBe('');
			expect(fetched?.fingerprint).toBe('');
			expect(fetched?.label).toBe('');
			expect(fetched?.browser).toBe('');
			expect(fetched?.device).toBe('');
			expect(fetched?.ip).toBe('');
			expect(fetched?.os).toBe('');
			// Some stores persist empty scope as [] rather than undefined.
			if (fetched?.scope === undefined) {
				expect(fetched.scope).toBeUndefined();
			} else {
				expect(fetched?.scope).toEqual([]);
			}
			expect(fetched?.issuedAt).toBeInstanceOf(Date);
			expect(fetched?.lastSeenAt).toBeInstanceOf(Date);
			expect(fetched?.expires).toBeInstanceOf(Date);
			expect(fetched?.expires!.getTime()).toBeGreaterThan(before);
			expectDatesClose(fetched!.issuedAt!, fetched!.lastSeenAt!);
		});

		it('requires a lookup key when fetching', async () => {
			await expect(store.get({})).rejects.toThrow(/At least one token lookup field/);
		});

		it('replaces matching tokens for same user/domain/fingerprint/client', async () => {
			await store.save(
				baseToken({
					refreshToken: 'r-old',
					accessToken: 'a-old',
					domain: 'example.com',
					fingerprint: 'fp1',
					clientId: 'client-1'
				})
			);
			await store.save(
				baseToken({
					refreshToken: 'r-new',
					accessToken: 'a-new',
					domain: 'example.com',
					fingerprint: 'fp1',
					clientId: 'client-1'
				})
			);

			const list = await store.list(1, { includeExpired: true });
			expect(list).toHaveLength(1);
			expect(list[0].refreshToken).toBe('r-new');
		});

		it('updates stored tokens with normalized metadata', async () => {
			const refreshToken = 'refresh-update';
			const nextExpiry = new Date(Date.now() + 10_000);

			await store.save(baseToken({ refreshToken }));

			const updated = await store.update({
				refreshToken,
				scope: ['read', 'write'],
				domain: 'updated.com',
				fingerprint: 'fp-updated',
				browser: 'br',
				device: 'dev',
				ip: '1.2.3.4',
				os: 'osx',
				refreshTtlSeconds: 42,
				sessionCookie: true,
				loginType: 'password',
				expires: nextExpiry
			});

			expect(updated).toBe(true);
			const fetched = await store.get({ refreshToken });
			expect(fetched?.scope).toEqual(['read', 'write']);
			expect(fetched?.domain).toBe('updated.com');
			expect(fetched?.fingerprint).toBe('fp-updated');
			expect(fetched?.browser).toBe('br');
			expect(fetched?.device).toBe('dev');
			expect(fetched?.ip).toBe('1.2.3.4');
			expect(fetched?.os).toBe('osx');
			expect(fetched?.refreshTtlSeconds).toBe(42);
			expect(fetched?.loginType).toBe('password');
			const fetchedExpiry = fetched?.expires?.getTime();
			expect(fetchedExpiry).toBeDefined();
			expect(Math.abs((fetchedExpiry ?? 0) - nextExpiry.getTime())).toBeLessThanOrEqual(1000);
		});

		it('ignores null values for non-nullable fields during updates', async () => {
			const refreshToken = 'refresh-null-ignored';
			const originalAccess = 'access-original';
			await store.save(baseToken({ refreshToken, accessToken: originalAccess }));

			const updated = await store.update({
				refreshToken,
				accessToken: null as unknown as string,
				expires: null as unknown as Date,
				issuedAt: null as unknown as Date,
				lastSeenAt: null as unknown as Date,
				domain: 'updated.example'
			});

			expect(updated).toBe(true);
			const fetched = await store.get({ refreshToken });
			expect(fetched).not.toBeNull();
			expect(fetched?.accessToken).toBe(originalAccess);
			expect(fetched?.domain).toBe('updated.example');
		});

		it('deletes tokens by query fields', async () => {
			const userId = testUserId;
			await store.save(
				baseToken({
					userId,
					refreshToken: 'r-1',
					clientId: 'c1',
					accessToken: 'a-1'
				})
			);
			await store.save(
				baseToken({
					userId,
					refreshToken: 'r-2',
					clientId: 'c2',
					accessToken: 'a-2'
				})
			);

			const removed = await store.delete({ clientId: 'c1' });
			expect(removed).toBeGreaterThanOrEqual(1);

			const remaining = await store.list(userId, {
				includeExpired: true
			});
			expect(remaining.map((t) => t.refreshToken).sort()).toEqual(['r-2']);
		});

		it('supports session id lookup and revocation', async () => {
			const userId = testUserId;
			await store.save(
				baseToken({
					userId,
					refreshToken: 'r-session',
					accessToken: 'a-session',
					sessionId: 'session-handle-1'
				})
			);

			const fetched = await store.get({
				sessionId: 'session-handle-1',
				userId
			});
			expect(fetched?.refreshToken).toBe('r-session');

			const removed = await store.delete({
				sessionId: 'session-handle-1',
				userId
			});
			expect(removed).toBe(1);
			expect(await store.get({ refreshToken: 'r-session' }, { includeExpired: true })).toBeNull();
		});

		it('supports multiple client sessions per user and targeted revocation', async () => {
			const userId = testUserId;
			await store.save(
				baseToken({
					userId,
					refreshToken: 'r-web',
					accessToken: 'a-web',
					clientId: 'web',
					domain: 'web.example',
					fingerprint: 'fp-web'
				})
			);
			await store.save(
				baseToken({
					userId,
					refreshToken: 'r-mobile',
					accessToken: 'a-mobile',
					clientId: 'mobile',
					domain: 'm.example',
					fingerprint: 'fp-mobile'
				})
			);
			await store.save(
				baseToken({
					userId,
					refreshToken: 'r-cli',
					accessToken: 'a-cli',
					clientId: 'cli',
					domain: 'cli.example',
					fingerprint: 'fp-cli'
				})
			);

			const before = await store.list(userId, { includeExpired: true });
			expect(before.map((t) => t.refreshToken).sort()).toEqual(['r-cli', 'r-mobile', 'r-web']);

			const removedClient = await store.delete({
				clientId: 'mobile',
				userId
			});
			expect(removedClient).toBeGreaterThanOrEqual(1);
			const afterClient = await store.list(userId, {
				includeExpired: true
			});
			expect(afterClient.map((t) => t.refreshToken).sort()).toEqual(['r-cli', 'r-web']);

			const removedDomain = await store.delete({
				domain: 'cli.example',
				userId
			});
			expect(removedDomain).toBeGreaterThanOrEqual(1);
			const remaining = await store.list(userId, {
				includeExpired: true
			});
			expect(remaining.map((t) => t.refreshToken)).toEqual(['r-web']);
		});

		it('honors includeExpired flag', async () => {
			const userId = testUserId;
			await store.save(
				baseToken({
					userId,
					refreshToken: 'expired',
					accessToken: 'a-exp',
					clientId: 'c-exp',
					expires: new Date(Date.now() - 1_000)
				})
			);
			await store.save(
				baseToken({
					userId,
					refreshToken: 'active',
					accessToken: 'a-act',
					clientId: 'c-act',
					expires: new Date(Date.now() + 10_000)
				})
			);

			const activeOnly = await store.list(userId);
			expect(activeOnly.map((t) => t.refreshToken)).toEqual(['active']);

			const all = await store.list(userId, { includeExpired: true });
			expect(all.map((t) => t.refreshToken).sort()).toEqual(['active', 'expired']);
		});

		it('provides JWT helpers on the store', () => {
			const sign = store.jwtSign({ uid: 'user-1' }, 'secret', 60);
			expect(sign.success).toBe(true);
			const verify = store.jwtVerify<{ uid: string }>(sign.token!, 'secret');
			expect(verify.success).toBe(true);
			expect(verify.data?.uid).toBe('user-1');
			const decoded = store.jwtDecode<{ uid: string }>(sign.token!);
			expect(decoded.success).toBe(true);
			expect(decoded.data?.uid).toBe('user-1');
		});

		it('returns cloned date fields so callers cannot mutate stored dates by reference', async () => {
			const refreshToken = 'clone-dates-refresh';
			await store.save(baseToken({ refreshToken }));

			const first = await store.get({ refreshToken });
			expect(first).not.toBeNull();
			expect(first?.expires).toBeInstanceOf(Date);
			if (!first?.expires) {
				throw new Error('Expected expires to be defined');
			}

			const original = first.expires.getTime();
			first.expires.setTime(0);

			const second = await store.get({ refreshToken });
			expect(second).not.toBeNull();
			expect(second?.expires?.getTime()).toBe(original);
		});
	});
}
