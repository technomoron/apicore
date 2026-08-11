import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import request from 'supertest';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { JsonApiKeyStore } from '../../src/api-key/json.js';
import { MemoryApiKeyStore } from '../../src/api-key/memory.js';
import { BaseAuthAdapter } from '../../src/auth-api/storage.js';
import { MemoryTokenStore } from '../../src/token/memory.js';
import { createServer, signToken, type TestUser } from '../helpers/test-server';

function setCookieValue(setCookie: string[] | undefined, name: string): string | null {
	const entry = setCookie?.find((cookie) => cookie.startsWith(`${name}=`));
	if (!entry) {
		return null;
	}
	return entry.slice(name.length + 1).split(';', 1)[0] ?? null;
}

describe('Route authentication', () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});

	afterEach(() => {
		vi.resetAllMocks();
	});

	it('handles public routes without authentication', async () => {
		const server = createServer();
		const response = await request(server.app).get('/api/example/public');
		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ ok: true });
	});

	it('optional auth allows anonymous access', async () => {
		const server = createServer();
		const response = await request(server.app).get('/api/example/optional');
		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ authenticated: false });
	});

	it('does not auto-refresh optional routes by default', async () => {
		const server = createServer();
		const refresh = server.jwtSign({ uid: 'user-1', role: 'any' }, server.config.refreshSecret, 60 * 60);
		if (!refresh.success || !refresh.token) {
			throw new Error(refresh.error ?? 'Failed to sign refresh token');
		}

		await server.storage.storeToken({
			accessToken: 'access-unused',
			refreshToken: refresh.token,
			userId: 'user-1',
			expires: new Date(Date.now() + 60 * 60 * 1000)
		});

		const response = await request(server.app)
			.get('/api/example/optional')
			.set('Cookie', [`${server.config.refreshCookie}=${refresh.token}`]);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ authenticated: false });
	});

	it('auto-refreshes optional routes when enabled', async () => {
		const server = createServer({ refreshMaybe: true });
		const refresh = server.jwtSign({ uid: 'user-1', role: 'any' }, server.config.refreshSecret, 60 * 60);
		if (!refresh.success || !refresh.token) {
			throw new Error(refresh.error ?? 'Failed to sign refresh token');
		}

		await server.storage.storeToken({
			accessToken: 'access-unused',
			refreshToken: refresh.token,
			userId: 'user-1',
			expires: new Date(Date.now() + 60 * 60 * 1000)
		});

		const response = await request(server.app)
			.get('/api/example/optional')
			.set('Cookie', [`${server.config.refreshCookie}=${refresh.token}`]);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ authenticated: true });

		const setCookie = response.headers['set-cookie'];
		expect(Array.isArray(setCookie)).toBe(true);
		expect(setCookie.join('\n')).toContain(`${server.config.accessCookie}=`);
	});

	it('rejects refresh cookies whose user does not match the stored session', async () => {
		const server = createServer();
		const refresh = server.jwtSign({ uid: 'admin-1', role: 'admin' }, server.config.refreshSecret, 60 * 60);
		if (!refresh.success || !refresh.token) {
			throw new Error(refresh.error ?? 'Failed to sign refresh token');
		}
		await server.storage.storeToken({
			accessToken: 'access-unused',
			refreshToken: refresh.token,
			userId: 'user-1',
			expires: new Date(Date.now() + 60 * 60 * 1000)
		});

		const response = await request(server.app)
			.get('/api/example/secure')
			.set('Cookie', [`${server.config.refreshCookie}=${refresh.token}`]);

		expect(response.status).toBe(401);
		expect(response.body.message).toBe('Authorization token is required (Bearer/cookie)');
		expect(await server.storage.getToken({ refreshToken: refresh.token })).not.toBeNull();
	});

	it('authorizes bearer token requests', async () => {
		const server = createServer();
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app).get('/api/example/secure').set('Authorization', `Bearer ${token}`);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ uid: 'user-1' });
	});

	it('supports token params from request body when bearer is missing', async () => {
		const server = createServer({ tokenParam: 'token' });
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app).get('/api/example/secure').send({ token });

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ uid: 'user-1' });
	});

	it('supports token params from query when tokenParamLocation is body-query', async () => {
		const server = createServer({
			tokenParam: 'token',
			tokenParamLocation: 'body-query'
		});
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app).get(`/api/example/secure?token=${encodeURIComponent(token)}`);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ uid: 'user-1' });
	});

	it('prioritizes bearer over token params when both are present', async () => {
		const server = createServer({ tokenParam: 'token' });
		const bearer = signToken(server, { uid: 'admin-1', role: 'admin' });
		const fallback = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app)
			.get('/api/example/secure')
			.set('Authorization', `Bearer ${bearer}`)
			.send({ token: fallback });

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ uid: 'admin-1' });
	});

	it('supports token params from query when tokenParamLocation is query', async () => {
		const server = createServer({
			tokenParam: 'token',
			tokenParamLocation: 'query'
		});
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app).get(`/api/example/secure?token=${encodeURIComponent(token)}`);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ uid: 'user-1' });
	});

	it('rejects token in body when tokenParamLocation is query', async () => {
		const server = createServer({
			tokenParam: 'token',
			tokenParamLocation: 'query'
		});
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app).get('/api/example/secure').send({ token });

		expect(response.status).toBe(401);
	});

	it('rejects token in query when tokenParamLocation is body', async () => {
		// hydrateGetBody: false prevents GET query params from being copied into req.body
		const server = createServer({
			tokenParam: 'token',
			tokenParamLocation: 'body',
			hydrateGetBody: false
		});
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app).get(`/api/example/secure?token=${encodeURIComponent(token)}`);

		expect(response.status).toBe(401);
	});

	it('allows auth cookie when header is missing', async () => {
		const server = createServer();
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app)
			.get('/api/example/secure')
			.set('Cookie', [`${server.config.accessCookie}=${token}`]);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ uid: 'user-1' });
	});

	it('respects the configured accessCookie name', async () => {
		const server = createServer({ accessCookie: 'access' });
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app)
			.get('/api/example/secure')
			.set('Cookie', [`access=${token}`]);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ uid: 'user-1' });
	});

	it('rejects missing auth on secure routes', async () => {
		const server = createServer();
		const response = await request(server.app).get('/api/example/secure');
		expect(response.status).toBe(401);
		expect(response.body.message).toBe('Authorization token is required (Bearer/cookie)');
	});

	it('rejects invalid auth cookies when header is missing', async () => {
		const server = createServer();
		const response = await request(server.app)
			.get('/api/example/secure')
			.set('Cookie', [`${server.config.accessCookie}=not-a-valid-jwt`]);

		expect(response.status).toBe(401);
		expect(response.body.message).toContain('Unauthorized Access');
	});

	it('auto-refreshes expired access tokens when a valid refresh cookie is present', async () => {
		const server = createServer();
		const expiredAccess = signToken(server, { uid: 'user-1', role: 'any' }, -10);
		const refresh = server.jwtSign({ uid: 'user-1', role: 'any' }, server.config.refreshSecret, 60 * 60);
		if (!refresh.success || !refresh.token) {
			throw new Error(refresh.error ?? 'Failed to sign refresh token');
		}

		await server.storage.storeToken({
			accessToken: expiredAccess,
			refreshToken: refresh.token,
			userId: 'user-1',
			expires: new Date(Date.now() + 60 * 60 * 1000)
		});

		const response = await request(server.app)
			.get('/api/example/secure')
			.set('Cookie', [
				`${server.config.accessCookie}=${expiredAccess}`,
				`${server.config.refreshCookie}=${refresh.token}`
			]);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ uid: 'user-1' });

		const setCookie = response.headers['set-cookie'];
		expect(Array.isArray(setCookie)).toBe(true);
		expect(setCookie.join('\n')).toContain(`${server.config.accessCookie}=`);
		const rotatedRefreshToken = setCookieValue(setCookie, server.config.refreshCookie);
		expect(rotatedRefreshToken).not.toBeNull();

		const updated = await server.storage.getToken({
			refreshToken: rotatedRefreshToken ?? ''
		});
		expect(updated).not.toBeNull();
		expect(updated?.accessToken).not.toBe(expiredAccess);
	});

	it('parses comma-separated x-forwarded-proto when deciding cookie Secure under auto mode', async () => {
		const server = createServer({ cookieSecure: 'auto', trustProxy: true });
		const expiredAccess = signToken(server, { uid: 'user-1', role: 'any' }, -10);
		const refresh = server.jwtSign({ uid: 'user-1', role: 'any' }, server.config.refreshSecret, 60 * 60);
		if (!refresh.success || !refresh.token) {
			throw new Error(refresh.error ?? 'Failed to sign refresh token');
		}

		await server.storage.storeToken({
			accessToken: expiredAccess,
			refreshToken: refresh.token,
			userId: 'user-1',
			expires: new Date(Date.now() + 60 * 60 * 1000)
		});

		const response = await request(server.app)
			.get('/api/example/secure')
			.set('x-forwarded-proto', 'https,http')
			.set('Cookie', [
				`${server.config.accessCookie}=${expiredAccess}`,
				`${server.config.refreshCookie}=${refresh.token}`
			]);

		expect(response.status).toBe(200);

		const setCookie = response.headers['set-cookie'];
		expect(Array.isArray(setCookie)).toBe(true);
		expect(setCookie.join('\n')).toContain(`${server.config.accessCookie}=`);
		expect(setCookie.join('\n')).toContain('Secure');
	});

	it('does not treat non-localhost origins as localhost when resolving cookie domain in dev mode', async () => {
		const server = createServer({
			devMode: true,
			cookieDomain: 'example.com',
			origins: ['https://notlocalhost.evil.com']
		});
		const expiredAccess = signToken(server, { uid: 'user-1', role: 'any' }, -10);
		const refresh = server.jwtSign({ uid: 'user-1', role: 'any' }, server.config.refreshSecret, 60 * 60);
		if (!refresh.success || !refresh.token) {
			throw new Error(refresh.error ?? 'Failed to sign refresh token');
		}

		await server.storage.storeToken({
			accessToken: expiredAccess,
			refreshToken: refresh.token,
			userId: 'user-1',
			expires: new Date(Date.now() + 60 * 60 * 1000)
		});

		const response = await request(server.app)
			.get('/api/example/secure')
			.set('Origin', 'https://notlocalhost.evil.com')
			.set('Cookie', [
				`${server.config.accessCookie}=${expiredAccess}`,
				`${server.config.refreshCookie}=${refresh.token}`
			]);

		expect(response.status).toBe(200);
		const setCookie = response.headers['set-cookie'];
		expect(Array.isArray(setCookie)).toBe(true);
		expect(setCookie.join('\n')).toContain('Domain=example.com');
	});

	it('auto-refreshes expired tokens for strict routes and validates storage', async () => {
		const server = createServer();
		const expiredAccess = signToken(server, { uid: 'user-1', role: 'any' }, -10);
		const refresh = server.jwtSign({ uid: 'user-1', role: 'any' }, server.config.refreshSecret, 60 * 60);
		if (!refresh.success || !refresh.token) {
			throw new Error(refresh.error ?? 'Failed to sign refresh token');
		}

		await server.storage.storeToken({
			accessToken: expiredAccess,
			refreshToken: refresh.token,
			userId: 'user-1',
			expires: new Date(Date.now() + 60 * 60 * 1000)
		});

		const response = await request(server.app)
			.get('/api/example/strict')
			.set('Cookie', [
				`${server.config.accessCookie}=${expiredAccess}`,
				`${server.config.refreshCookie}=${refresh.token}`
			]);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ uid: 'user-1' });
	});

	it('recovers strict auth when the access token is not stored but refresh cookie is valid', async () => {
		const server = createServer();

		const storedAccess = signToken(server, { uid: 'user-1', role: 'any', tag: 'stored' }, 60 * 60);
		const refresh = server.jwtSign(
			{ uid: 'user-1', role: 'any', tag: 'stored' },
			server.config.refreshSecret,
			60 * 60
		);
		if (!refresh.success || !refresh.token) {
			throw new Error(refresh.error ?? 'Failed to sign refresh token');
		}

		await server.storage.storeToken({
			accessToken: storedAccess,
			refreshToken: refresh.token,
			userId: 'user-1',
			expires: new Date(Date.now() + 60 * 60 * 1000)
		});

		const unstoredAccess = signToken(server, { uid: 'user-1', role: 'any', tag: 'unstored' }, 60 * 60);

		const response = await request(server.app)
			.get('/api/example/strict')
			.set('Authorization', `Bearer ${unstoredAccess}`)
			.set('Cookie', [`${server.config.refreshCookie}=${refresh.token}`]);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ uid: 'user-1' });

		const updated = await server.storage.getToken({
			refreshToken: refresh.token
		});
		expect(updated).not.toBeNull();
		expect(updated?.accessToken).not.toBe(unstoredAccess);
	});

	it('resolves API key tokens', async () => {
		const server = createServer();
		const response = await request(server.app).get('/api/example/apikey').set('Authorization', 'Bearer key-123');

		expect(response.status).toBe(200);
		expect(response.body.data.uid).toBe('api-user');
		expect(response.body.data.token).toBe('key-123');
	});

	it('resolves API keys from a configured memory key store', async () => {
		const server = createServer({ apiKeyEnabled: true });
		server.apiKeys.clear();
		server.setApiKeyStore(
			new MemoryApiKeyStore({
				keys: [
					{
						id: 'sync-job',
						secret: 'memory-secret',
						uid: 'api-user',
						meta: { purpose: 'test' }
					}
				]
			})
		);

		const response = await request(server.app)
			.get('/api/example/whoami')
			.set('Authorization', 'Bearer memory-secret');

		expect(response.status).toBe(200);
		expect(response.body.data.uid).toBe('api-user');
		expect(response.body.data.authMethod).toBe('apikey');
		expect(response.body.data.token).toBeUndefined();

		const stored = await server.getApiKey('memory-secret');
		expect(stored).toEqual({
			id: 'sync-job',
			uid: 'api-user',
			meta: { purpose: 'test' }
		});
	});

	it('resolves API keys from a validated JSON key store', async () => {
		const dir = await mkdtemp(path.join(tmpdir(), 'apicore-keys-'));
		try {
			const file = path.join(dir, 'api-keys.json');
			await writeFile(
				file,
				JSON.stringify({
					version: 1,
					keys: [
						{
							id: 'json-key',
							secret: 'json-secret',
							uid: 42,
							euid: 'user-1'
						}
					]
				})
			);
			const server = createServer({ apiKeyEnabled: true });
			server.apiKeys.clear();
			server.setApiKeyStore(new JsonApiKeyStore({ file }));

			const response = await request(server.app)
				.get('/api/example/whoami')
				.set('Authorization', 'Bearer json-secret');

			expect(response.status).toBe(200);
			expect(response.body.data.uid).toBe('user-1');
			expect(response.body.data.realUid).toBe(42);
			expect(response.body.data.isImpersonating).toBe(true);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it('rejects malformed JSON API key records when the store is created', async () => {
		const dir = await mkdtemp(path.join(tmpdir(), 'apicore-keys-'));
		try {
			const file = path.join(dir, 'api-keys.json');
			await writeFile(
				file,
				JSON.stringify({
					version: 1,
					keys: [{ id: 'missing-secret', uid: 'api-user' }]
				})
			);

			expect(() => new JsonApiKeyStore({ file })).toThrow(/requires a non-empty secret/);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it('supports API key tokens from token params when bearer is missing', async () => {
		const server = createServer({ tokenParam: 'token' });
		const response = await request(server.app).get('/api/example/apikey').send({ token: 'key-123' });

		expect(response.status).toBe(200);
		expect(response.body.data.uid).toBe('api-user');
		expect(response.body.data.token).toBe('key-123');
	});

	it('supports API key tokens from query param when tokenParamLocation is query', async () => {
		const server = createServer({
			tokenParam: 'token',
			tokenParamLocation: 'query'
		});
		const response = await request(server.app).get('/api/example/apikey?token=key-123');

		expect(response.status).toBe(200);
		expect(response.body.data.uid).toBe('api-user');
		expect(response.body.data.token).toBe('key-123');
	});

	it('enforces API key prefix via tokenParam', async () => {
		const server = createServer({
			tokenParam: 'token',
			apiKeyPrefix: 'apikey-'
		});
		const denied = await request(server.app).get('/api/example/apikey').send({ token: 'key-123' });
		expect(denied.status).toBe(401);
		expect(denied.body.message).toBe('Invalid API Key');

		const allowed = await request(server.app).get('/api/example/apikey').send({ token: 'apikey-key-123' });
		expect(allowed.status).toBe(200);
		expect(allowed.body.data).toEqual({
			uid: 'api-user',
			token: 'key-123'
		});
	});

	it('enforces authorization class logic', async () => {
		const server = createServer();
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app).get('/api/example/admin').set('Authorization', `Bearer ${token}`);

		expect(response.status).toBe(403);
		expect(response.body.message).toBe('Forbidden');
	});

	it('allows admin users through authorization', async () => {
		const server = createServer();
		const token = signToken(server, { uid: 'admin-1', role: 'admin' });
		const response = await request(server.app).get('/api/example/admin').set('Authorization', `Bearer ${token}`);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ role: 'admin' });
	});

	it('accepts API keys on secure routes', async () => {
		const server = createServer({ apiKeyEnabled: true });
		const response = await request(server.app).get('/api/example/secure').set('Authorization', 'Bearer key-123');

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ uid: 'api-user' });
	});

	it('rejects unstored tokens when validateTokens is enabled', async () => {
		const server = createServer({ validateTokens: true });
		const token = signToken(server, { uid: 'user-1', role: 'any' });

		const denied = await request(server.app).get('/api/example/secure').set('Authorization', `Bearer ${token}`);
		expect(denied.status).toBe(401);
		expect(denied.body.message).toBe('Authorization token is no longer valid');

		await server.storage.storeToken({
			accessToken: token,
			refreshToken: 'refresh-validate',
			userId: 'user-1'
		});

		const allowed = await request(server.app).get('/api/example/secure').set('Authorization', `Bearer ${token}`);
		expect(allowed.status).toBe(200);
		expect(allowed.body.data).toEqual({ uid: 'user-1' });
	});

	it('uses the configured external tokenStore when validating strict routes', async () => {
		class ThinAuthStorage extends BaseAuthAdapter<TestUser, Omit<TestUser, 'password'>> {
			constructor(private readonly users: Map<string, TestUser>) {
				super();
			}

			public override async getUser(identifier: string | number): Promise<TestUser | null> {
				return this.users.get(String(identifier)) ?? null;
			}

			public override getUserPasswordHash(user: TestUser): string {
				return user.password;
			}

			public override getUserId(user: TestUser): string {
				return user.id;
			}

			public override filterUser(user: TestUser): Omit<TestUser, 'password'> {
				const { password: _password, ...safe } = user;
				void _password;
				return safe;
			}

			public override async verifyPassword(password: string, hash: string): Promise<boolean> {
				return password === hash;
			}
		}

		const server = createServer({ tokenStore: new MemoryTokenStore() });
		server.authStorage(new ThinAuthStorage(server.users));

		const token = signToken(server, { uid: 'user-1', role: 'any' });
		await server.storeToken({
			accessToken: token,
			refreshToken: 'refresh-external-store',
			userId: 'user-1'
		});

		const allowed = await request(server.app).get('/api/example/strict').set('Authorization', `Bearer ${token}`);
		expect(allowed.status).toBe(200);
		expect(allowed.body.data).toEqual({ uid: 'user-1' });
	});

	it('enforces strict routes regardless of global config', async () => {
		const server = createServer();
		const token = signToken(server, { uid: 'user-1', role: 'any' });

		const denied = await request(server.app).get('/api/example/strict').set('Authorization', `Bearer ${token}`);
		expect(denied.status).toBe(401);
		expect(denied.body.message).toBe('Authorization token is no longer valid');

		await server.storage.storeToken({
			accessToken: token,
			refreshToken: 'refresh-strict',
			userId: 'user-1'
		});

		const allowed = await request(server.app).get('/api/example/strict').set('Authorization', `Bearer ${token}`);
		expect(allowed.status).toBe(200);
		expect(allowed.body.data).toEqual({ uid: 'user-1' });
	});

	it('allows API keys to satisfy strict routes', async () => {
		const server = createServer({ apiKeyEnabled: true });
		const response = await request(server.app).get('/api/example/strict').set('Authorization', 'Bearer key-123');

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ uid: 'api-user' });
	});

	it('supports configurable API key prefixes', async () => {
		const server = createServer({ apiKeyPrefix: 'apikey-' });
		const denied = await request(server.app).get('/api/example/apikey').set('Authorization', 'Bearer key-123');
		expect(denied.status).toBe(401);
		expect(denied.body.message).toBe('Invalid API Key');

		const allowed = await request(server.app)
			.get('/api/example/apikey')
			.set('Authorization', 'Bearer apikey-key-123');
		expect(allowed.status).toBe(200);
		expect(allowed.body.data).toEqual({
			uid: 'api-user',
			token: 'key-123'
		});
	});

	it('API key without euid acts as itself with no impersonation', async () => {
		const server = createServer({ apiKeyEnabled: true });
		const response = await request(server.app).get('/api/example/whoami').set('Authorization', 'Bearer key-123');

		expect(response.status).toBe(200);
		expect(response.body.data.uid).toBe('api-user');
		expect(response.body.data.realUid).toBe('api-user');
		expect(response.body.data.isImpersonating).toBe(false);
		expect(response.body.data.authMethod).toBe('apikey');
	});

	it('API key with euid impersonates the target user', async () => {
		const server = createServer({ apiKeyEnabled: true });
		const response = await request(server.app)
			.get('/api/example/whoami')
			.set('Authorization', 'Bearer key-impersonate');

		expect(response.status).toBe(200);
		expect(response.body.data.uid).toBe('user-1');
		expect(response.body.data.realUid).toBe('api-user');
		expect(response.body.data.isImpersonating).toBe(true);
		expect(response.body.data.authMethod).toBe('apikey');
	});

	it('reports authMethod bearer for JWT bearer tokens', async () => {
		const server = createServer();
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app).get('/api/example/whoami').set('Authorization', `Bearer ${token}`);

		expect(response.status).toBe(200);
		expect(response.body.data.authMethod).toBe('bearer');
		expect(response.body.data.isImpersonating).toBe(false);
	});

	it('reports authMethod cookie for cookie-based auth', async () => {
		const server = createServer();
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app)
			.get('/api/example/whoami')
			.set('Cookie', [`${server.config.accessCookie}=${token}`]);

		expect(response.status).toBe(200);
		expect(response.body.data.authMethod).toBe('cookie');
	});

	it('reports authMethod param for tokenParam-based auth', async () => {
		const server = createServer({ tokenParam: 'token' });
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const response = await request(server.app).get('/api/example/whoami').send({ token });

		expect(response.status).toBe(200);
		expect(response.body.data.authMethod).toBe('param');
	});
});
