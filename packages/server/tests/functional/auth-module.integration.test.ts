import { createHash } from 'node:crypto';

import { isoBase64URL } from '@simplewebauthn/server/helpers';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ApiModule } from '../../src/api-module';
import { ApiError } from '../../src/apicore-server';
import ApiServer from '../../src/apicore-server';
import AuthModule from '../../src/auth-api/auth-module';
import { MemAuthStore } from '../../src/auth-api/mem-auth-store';
import { BaseAuthAdapter } from '../../src/auth-api/storage';

interface AuthHarness {
	server: ApiServer;
	store: MemAuthStore;
	agent: request.SuperTest<request.Test>;
	userId: number;
}

const userInput = {
	login: 'sally',
	email: 'sally@example.com',
	password: 'super-secret'
};

const targetUserInput = {
	login: 'alex',
	email: 'alex@example.com',
	password: 'target-secret'
};

const serverConfig = {
	apiBasePath: '/api',
	accessSecret: 'access-secret',
	refreshSecret: 'refresh-secret',
	accessCookie: 'access',
	refreshCookie: 'refresh',
	cookieDomain: ''
} as const;

async function createAuthHarness(
	overrides: Partial<ConstructorParameters<typeof ApiServer>[0]> = {}
): Promise<AuthHarness> {
	const store = new MemAuthStore();
	await store.initialise();
	const user = await store.userStore.createUser(userInput);

	const config = { ...serverConfig, ...overrides };
	const server = new ApiServer(config).authStorage(store);
	const authModule = new AuthModule({ defaultDomain: config.cookieDomain });
	server.authModule(authModule);
	server.api(authModule);

	const agent = request(server.app) as unknown as request.SuperTest<request.Test>;
	const userId = Number(store.getUserId(user));

	return { server, store, agent, userId };
}

describe('AuthModule integration', () => {
	let harness: AuthHarness;

	beforeEach(async () => {
		harness = await createAuthHarness();
	});

	afterEach(async () => {
		await harness.store.close();
	});

	it('logs in, refreshes tokens, resolves identity, and logs out', async () => {
		const loginResponse = await harness.agent
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });

		expect(loginResponse.status).toBe(200);
		expect(loginResponse.body.code).toBe(200);
		const loginData = loginResponse.body.data;
		expect(typeof loginData.accessToken).toBe('string');
		expect(typeof loginData.refreshToken).toBe('string');
		expect(loginData.user.login).toBe(userInput.login);
		expect(loginData.user).not.toHaveProperty('password');

		const refreshToken = loginData.refreshToken as string;

		const refreshResponse = await harness.agent.post('/api/auth/v1/refresh').send({ refreshToken });
		expect(refreshResponse.status).toBe(200);
		expect(refreshResponse.body.code).toBe(200);
		const refreshed = refreshResponse.body.data;
		expect(refreshed.user).toBeUndefined();
		expect(refreshed.ruser).toBeUndefined();

		const me = await harness.agent
			.get('/api/auth/v1/me')
			.set('authorization', `Bearer ${refreshed.accessToken as string}`);

		expect(me.status).toBe(200);
		expect(me.body.code).toBe(200);
		expect(me.body.data.user.login).toBe(userInput.login);
		expect(me.body.data.user).not.toHaveProperty('password');
		expect(me.body.data.ruser).toBeUndefined();

		const activeRefreshToken = refreshed.refreshToken as string;

		const logout = await harness.agent.post('/api/auth/v1/logout').send({ refreshToken: activeRefreshToken });

		expect(logout.status).toBe(200);
		expect(logout.body.data.revoked).toBe(1);

		const denied = await harness.agent.post('/api/auth/v1/refresh').send({ refreshToken: activeRefreshToken });
		expect(denied.status).toBe(401);
	});

	it('lists and revokes sessions by non-secret session id', async () => {
		const loginResponse = await harness.agent.post('/api/auth/v1/login').send({
			login: userInput.login,
			password: userInput.password,
			label: 'Work laptop',
			browser: 'Firefox',
			device: 'desktop'
		});

		expect(loginResponse.status).toBe(200);
		const accessToken = loginResponse.body.data.accessToken as string;
		const refreshToken = loginResponse.body.data.refreshToken as string;

		const sessions = await harness.agent
			.get('/api/auth/v1/me/sessions')
			.set('authorization', `Bearer ${accessToken}`);

		expect(sessions.status).toBe(200);
		expect(sessions.body.data.sessions).toHaveLength(1);
		const session = sessions.body.data.sessions[0];
		expect(typeof session.sessionId).toBe('string');
		expect(session.sessionId).not.toBe(refreshToken);
		expect(session.current).toBe(true);
		expect(session.label).toBe('Work laptop');
		expect(session.browser).toBe('Firefox');
		expect(session.device).toBe('desktop');
		expect(session.tokenHint).toBe(`...${refreshToken.slice(-6)}`);
		expect(session).not.toHaveProperty('refreshToken');
		expect(session).not.toHaveProperty('accessToken');

		const revoke = await harness.agent
			.delete(`/api/auth/v1/me/sessions/${encodeURIComponent(session.sessionId as string)}`)
			.set('authorization', `Bearer ${accessToken}`);

		expect(revoke.status).toBe(200);
		expect(revoke.body.data.revoked).toBe(1);

		const denied = await harness.agent.post('/api/auth/v1/refresh').send({ refreshToken });
		expect(denied.status).toBe(401);
	});

	it('omits stored tokens that do not have a session id from session listings', async () => {
		const loginResponse = await harness.agent
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });

		expect(loginResponse.status).toBe(200);
		const accessToken = loginResponse.body.data.accessToken as string;
		const refreshToken = loginResponse.body.data.refreshToken as string;
		const tokenStore = harness.store.tokenStore as unknown as {
			tokens: Map<string, { sessionId?: string }>;
		};
		const stored = tokenStore.tokens.get(refreshToken);
		if (!stored) {
			throw new Error('Expected login token to be stored');
		}
		delete stored.sessionId;

		const sessions = await harness.agent
			.get('/api/auth/v1/me/sessions')
			.set('authorization', `Bearer ${accessToken}`);

		expect(sessions.status).toBe(200);
		expect(sessions.body.data.sessions).toEqual([]);
	});

	it('does not revoke another user session by session id', async () => {
		await harness.store.userStore.createUser(targetUserInput);
		const ownerLogin = await request(harness.server.app)
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });
		const targetLogin = await request(harness.server.app).post('/api/auth/v1/login').send({
			login: targetUserInput.login,
			password: targetUserInput.password
		});

		expect(ownerLogin.status).toBe(200);
		expect(targetLogin.status).toBe(200);

		const targetSessions = await request(harness.server.app)
			.get('/api/auth/v1/me/sessions')
			.set('authorization', `Bearer ${targetLogin.body.data.accessToken as string}`);
		const targetSessionId = targetSessions.body.data.sessions[0]?.sessionId as string | undefined;
		expect(typeof targetSessionId).toBe('string');

		const revoke = await request(harness.server.app)
			.delete(`/api/auth/v1/me/sessions/${encodeURIComponent(targetSessionId ?? '')}`)
			.set('authorization', `Bearer ${ownerLogin.body.data.accessToken as string}`);

		expect(revoke.status).toBe(200);
		expect(revoke.body.data.revoked).toBe(0);

		const refresh = await request(harness.server.app)
			.post('/api/auth/v1/refresh')
			.send({
				refreshToken: targetLogin.body.data.refreshToken as string
			});
		expect(refresh.status).toBe(200);
	});

	it('clears auth cookies when revoking the current session', async () => {
		const loginResponse = await harness.agent
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });

		expect(loginResponse.status).toBe(200);
		const accessToken = loginResponse.body.data.accessToken as string;
		const refreshToken = loginResponse.body.data.refreshToken as string;
		const sessions = await harness.agent
			.get('/api/auth/v1/me/sessions')
			.set('authorization', `Bearer ${accessToken}`);
		const sessionId = sessions.body.data.sessions[0]?.sessionId as string | undefined;
		expect(typeof sessionId).toBe('string');

		const revoke = await harness.agent
			.delete(`/api/auth/v1/me/sessions/${encodeURIComponent(sessionId ?? '')}`)
			.set('authorization', `Bearer ${accessToken}`);

		expect(revoke.status).toBe(200);
		expect(revoke.body.data.revoked).toBe(1);
		const setCookie = revoke.headers['set-cookie'] as string[] | undefined;
		expect(Array.isArray(setCookie)).toBe(true);
		const cookies = setCookie?.join('\n') ?? '';
		expect(cookies).toContain(`${harness.server.config.accessCookie}=;`);
		expect(cookies).toContain(`${harness.server.config.refreshCookie}=;`);

		const denied = await harness.agent.post('/api/auth/v1/refresh').send({ refreshToken });
		expect(denied.status).toBe(401);
	});

	it('returns field-level errors when login credentials are missing', async () => {
		const response = await harness.agent.post('/api/auth/v1/login').send({});

		expect(response.status).toBe(400);
		expect(response.body.code).toBe(400);
		expect(response.body.message).toBe('Validation failed');
		expect(response.body.errors).toHaveProperty('login');
		expect(response.body.errors).toHaveProperty('password');
	});

	it('performs password verification for unknown users', async () => {
		const verifyPassword = vi.spyOn(harness.store, 'verifyPassword');
		const response = await harness.agent
			.post('/api/auth/v1/login')
			.send({ login: 'missing-user', password: 'wrong-password' });

		expect(response.status).toBe(400);
		expect(response.body.message).toBe('Invalid credentials');
		expect(verifyPassword).toHaveBeenCalledOnce();
		expect(verifyPassword.mock.calls[0]?.[0]).toBe('wrong-password');
		expect(verifyPassword.mock.calls[0]?.[1]).toMatch(/^\$2[aby]\$/);
	});

	it('rejects unexpected query parameters on schema-backed auth routes', async () => {
		const response = await harness.agent
			.post('/api/auth/v1/login?unexpected=true')
			.send({ login: userInput.login, password: userInput.password });

		expect(response.status).toBe(400);
		expect(response.body.code).toBe(400);
		expect(response.body.message).toBe('Validation failed');
		expect(response.body.errors).toHaveProperty('unexpected');
	});

	it('rejects refresh requests when no refresh token is provided', async () => {
		const refresh = await harness.agent.post('/api/auth/v1/refresh').send({});
		expect(refresh.status).toBe(401);
		expect(refresh.body.message).toBe('Missing refresh token');
	});

	it('does not expose the legacy whoami endpoint', async () => {
		const response = await harness.agent.post('/api/auth/v1/whoami').send({});
		expect(response.status).toBe(404);
	});

	it('parses comma-separated x-forwarded-proto when deciding cookie Secure under auto mode', async () => {
		const localHarness = await createAuthHarness({ trustProxy: true });
		try {
			const loginResponse = await localHarness.agent
				.post('/api/auth/v1/login')
				.set('x-forwarded-proto', 'https,http')
				.send({ login: userInput.login, password: userInput.password });

			expect(loginResponse.status).toBe(200);
			expect(loginResponse.body.code).toBe(200);

			const setCookie = loginResponse.headers['set-cookie'];
			expect(Array.isArray(setCookie)).toBe(true);
			expect(setCookie.join('\n')).toContain(`${localHarness.server.config.accessCookie}=`);
			expect(setCookie.join('\n')).toContain(`${localHarness.server.config.refreshCookie}=`);
			expect(setCookie.join('\n')).toContain('Secure');
		} finally {
			await localHarness.store.close();
		}
	});

	it('does not treat non-localhost origins as localhost when resolving cookie domain in dev mode', async () => {
		const localHarness = await createAuthHarness({
			devMode: true,
			cookieDomain: 'example.com'
		});
		try {
			const loginResponse = await localHarness.agent
				.post('/api/auth/v1/login')
				.set('Origin', 'https://notlocalhost.evil.com')
				.send({ login: userInput.login, password: userInput.password });

			expect(loginResponse.status).toBe(200);
			const setCookie = loginResponse.headers['set-cookie'];
			expect(Array.isArray(setCookie)).toBe(true);
			expect(setCookie.join('\n')).toContain('Domain=example.com');
		} finally {
			await localHarness.store.close();
		}
	});

	it('signs refresh JWTs with the effective session or custom lifetime', async () => {
		const localHarness = await createAuthHarness({
			refreshExpiry: 3600,
			sessionRefreshExpiry: 30
		});
		try {
			for (const [keepSession, expectedLifetime] of [
				[false, 30],
				[45, 45]
			] as const) {
				const loginResponse = await localHarness.agent
					.post('/api/auth/v1/login')
					.send({ login: userInput.login, password: userInput.password, keepSession });

				expect(loginResponse.status).toBe(200);
				const decoded = localHarness.server.jwtDecode<{ exp?: number; iat?: number }>(
					loginResponse.body.data.refreshToken as string
				);
				expect(decoded.success).toBe(true);
				expect((decoded.data?.exp ?? 0) - (decoded.data?.iat ?? 0)).toBe(expectedLifetime);
			}
		} finally {
			await localHarness.store.close();
		}
	});

	it('keeps multiple sessions when fingerprint is omitted', async () => {
		const firstLogin = await harness.agent
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });

		expect(firstLogin.status).toBe(200);
		expect(firstLogin.body.code).toBe(200);
		expect(typeof firstLogin.body.data.accessToken).toBe('string');

		const initialTokens = await harness.store.tokenStore.list(harness.userId);
		expect(initialTokens.length).toBe(1);
		expect(typeof initialTokens[0]?.fingerprint).toBe('string');
		expect((initialTokens[0]?.fingerprint ?? '').length).toBeGreaterThan(0);

		const secondLogin = await harness.agent
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });

		expect(secondLogin.status).toBe(200);
		expect(secondLogin.body.code).toBe(200);

		const storedAfterSecond = await harness.store.getToken({
			userId: harness.userId,
			accessToken: firstLogin.body.data.accessToken as string
		});
		expect(storedAfterSecond).not.toBeNull();

		const tokens = await harness.store.tokenStore.list(harness.userId);
		expect(tokens.length).toBe(2);
		expect(new Set(tokens.map((token) => token.fingerprint)).size).toBe(2);
	});

	it('provides passkey challenges for existing users', async () => {
		const loginResponse = await harness.agent
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });

		expect(loginResponse.status).toBe(200);

		const registration = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.set('Authorization', `Bearer ${loginResponse.body.data.accessToken as string}`)
			.send({
				action: 'register',
				login: userInput.login,
				userId: harness.userId
			});

		expect(registration.status).toBe(200);
		expect(registration.body.code).toBe(200);
		expect(typeof registration.body.data.challenge).toBe('string');
		expect(registration.body.data.userId).toBe(harness.userId);

		const authentication = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.send({ action: 'authenticate', login: userInput.login });

		expect(authentication.status).toBe(200);
		expect(authentication.body.code).toBe(200);
		expect(authentication.body.data.challenge).toBeTypeOf('string');
		const allowCredentials = authentication.body?.data?.publicKey?.allowCredentials ?? [];
		expect(Array.isArray(allowCredentials)).toBe(true);
		expect(allowCredentials.length).toBe(0);
	});

	it('creates authenticate challenges without a user identifier for discoverable credentials', async () => {
		const response = await harness.agent.post('/api/auth/v1/passkeys/challenge').send({ action: 'authenticate' });

		expect(response.status).toBe(200);
		expect(response.body.code).toBe(200);
		expect(typeof response.body.data.challenge).toBe('string');
		const allowCredentials = response.body?.data?.publicKey?.allowCredentials ?? [];
		expect(Array.isArray(allowCredentials)).toBe(true);
		expect(allowCredentials.length).toBe(0);
		expect(response.body.data.userId ?? null).toBeNull();
	});

	it('does not error when authenticate challenges are requested for an unknown login', async () => {
		const response = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.send({ action: 'authenticate', login: 'missing-user' });

		expect(response.status).toBe(200);
		expect(response.body.code).toBe(200);
		expect(typeof response.body.data.challenge).toBe('string');
		const allowCredentials = response.body?.data?.publicKey?.allowCredentials ?? [];
		expect(Array.isArray(allowCredentials)).toBe(true);
		expect(allowCredentials.length).toBe(0);
		expect(response.body.data.userId ?? null).toBeNull();
	});

	it('rejects unauthenticated passkey registration challenges', async () => {
		const response = await harness.agent.post('/api/auth/v1/passkeys/challenge').send({
			action: 'register',
			login: userInput.login,
			userId: harness.userId
		});

		expect(response.status).toBe(401);
		expect(response.body.code).toBe(401);
		expect(response.body.message).toBe('Passkey registration requires authentication');
	});

	it('rejects passkey registration for another user', async () => {
		const otherUser = await harness.store.userStore.createUser(targetUserInput);
		const loginResponse = await harness.agent
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });

		expect(loginResponse.status).toBe(200);

		const response = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.set('Authorization', `Bearer ${loginResponse.body.data.accessToken as string}`)
			.send({
				action: 'register',
				login: otherUser.login,
				userId: otherUser.user_id
			});

		expect(response.status).toBe(403);
		expect(response.body.code).toBe(403);
		expect(response.body.message).toBe('Passkey registration is only allowed for the authenticated user');
	});

	it('rejects passkey challenge requests with invalid actions', async () => {
		const response = await harness.agent.post('/api/auth/v1/passkeys/challenge').send({ action: 'invalid-action' });

		expect(response.status).toBe(400);
		expect(response.body.code).toBe(400);
		expect(response.body.message).toBe('Validation failed');
		expect(response.body.errors).toHaveProperty('action');
	});

	it('deletes passkey credentials by credentialId in the URL path', async () => {
		if (!harness.store.passkeyStore) {
			throw new Error('Passkey store is not configured for MemAuthStore');
		}

		const credentialId = Buffer.from('credential-1');
		const credentialIdEncoded = isoBase64URL.fromBuffer(new Uint8Array(credentialId));

		await harness.store.passkeyStore.saveCredential({
			userId: harness.userId,
			credentialId,
			publicKey: Buffer.from('public-key-1'),
			counter: 0,
			transports: [],
			backedUp: false,
			deviceType: 'singleDevice',
			createdAt: new Date(),
			updatedAt: new Date()
		});

		const storedBefore = await harness.store.listUserCredentials(harness.userId);
		expect(storedBefore.length).toBe(1);

		const loginResponse = await harness.agent
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });

		expect(loginResponse.status).toBe(200);
		expect(loginResponse.body.code).toBe(200);

		const accessToken = loginResponse.body.data.accessToken as string;
		const response = await harness.agent
			.delete(`/api/auth/v1/passkeys/${credentialIdEncoded}`)
			.set('authorization', `Bearer ${accessToken}`);

		expect(response.status).toBe(200);
		expect(response.body.code).toBe(200);
		expect(response.body.data).toEqual({ deleted: true });

		const storedAfter = await harness.store.listUserCredentials(harness.userId);
		expect(storedAfter.length).toBe(0);
	});

	it('does not delete passkey credentials via request body', async () => {
		const response = await harness.agent.delete('/api/auth/v1/passkeys').send({ credentialId: 'any' });

		expect(response.status).toBe(404);
		expect(response.body.code).toBe(404);
		expect(response.body.message).toBe('No such endpoint: DELETE /api/auth/v1/passkeys');
	});

	it('allows API keys to call strict auth-module endpoints that require actor context', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		const user = await store.userStore.createUser(userInput);
		const userId = store.getUserId(user);

		class ApiKeyServer extends ApiServer {
			public override async getApiKey(token: string) {
				return token === 'key-123' ? { uid: userId } : null;
			}
		}

		const server = new ApiKeyServer({
			...serverConfig,
			apiKeyEnabled: true
		}).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).get('/api/auth/v1/passkeys').set('Authorization', 'Bearer key-123');

		expect(response.status).toBe(200);
		expect(response.body.code).toBe(200);
		expect(response.body.data).toEqual({ credentials: [] });

		await store.close();
	});

	it('returns real and effective user details when impersonating', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.userStore.createUser(userInput);
		await store.userStore.createUser(targetUserInput);

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain,
			canImpersonate: () => true
		});
		server.authModule(authModule);
		server.api(authModule);

		const loginResponse = await request(server.app)
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });

		expect(loginResponse.status).toBe(200);
		expect(loginResponse.body.code).toBe(200);

		const impersonation = await request(server.app)
			.post('/api/auth/v1/impersonations')
			.set('authorization', `Bearer ${loginResponse.body.data.accessToken as string}`)
			.send({ login: targetUserInput.login });

		expect(impersonation.status).toBe(200);
		expect(impersonation.body.code).toBe(200);
		expect(impersonation.body.data.user.login).toBe(targetUserInput.login);

		const refreshed = await request(server.app)
			.post('/api/auth/v1/refresh')
			.send({
				refreshToken: impersonation.body.data.refreshToken as string
			});

		expect(refreshed.status).toBe(200);
		expect(refreshed.body.code).toBe(200);
		expect(refreshed.body.data.user).toBeUndefined();
		expect(refreshed.body.data.ruser).toBeUndefined();

		const me = await request(server.app)
			.get('/api/auth/v1/me')
			.set('authorization', `Bearer ${refreshed.body.data.accessToken as string}`);

		expect(me.status).toBe(200);
		expect(me.body.code).toBe(200);
		expect(me.body.data.user.login).toBe(targetUserInput.login);
		expect(me.body.data.ruser?.login).toBe(userInput.login);
		expect(me.body.data.ruser).not.toHaveProperty('password');

		await store.close();
	});

	it('refreshes tokens that work with strict stored-token validation', async () => {
		class SecureModule extends ApiModule<ApiServer> {
			constructor() {
				super({ namespace: '/secure-test' });
			}

			public override defineRoutes() {
				return [
					{
						method: 'get',
						path: '/me',
						auth: { type: 'yes', req: 'any' },
						handler: async ({ tokenData }) => [200, { uid: tokenData?.uid ?? null }]
					}
				];
			}
		}

		const store = new MemAuthStore();
		await store.initialise();
		const user = await store.userStore.createUser(userInput);
		const userId = store.getUserId(user);

		const server = new ApiServer({
			...serverConfig,
			validateTokens: true
		}).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);
		server.api(new SecureModule());

		const loginResponse = await request(server.app)
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });

		expect(loginResponse.status).toBe(200);
		const refreshToken = loginResponse.body.data.refreshToken as string;

		const refresh = await request(server.app).post('/api/auth/v1/refresh').send({ refreshToken });
		expect(refresh.status).toBe(200);

		const rotatedRefreshToken = refresh.body.data.refreshToken as string;
		const stored = await store.getToken({
			refreshToken: rotatedRefreshToken
		});
		expect(stored).not.toBeNull();
		expect(typeof stored?.accessToken).toBe('string');

		const refreshedCookies = refresh.headers['set-cookie'] as string[] | undefined;
		expect(Array.isArray(refreshedCookies)).toBe(true);
		const secure = await request(server.app)
			.get('/api/secure-test/me')
			.set('Cookie', refreshedCookies ?? []);
		expect(secure.status, JSON.stringify({ status: secure.status, body: secure.body })).toBe(200);
		expect(secure.body.code).toBe(200);
		expect(secure.body.data.uid).toBe(String(userId));

		await store.close();
	});

	it('uses query parameters for impersonation-end metadata on DELETE /impersonations', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.userStore.createUser(userInput);
		await store.userStore.createUser(targetUserInput);

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain,
			canImpersonate: () => true
		});
		server.authModule(authModule);
		server.api(authModule);

		const loginResponse = await request(server.app)
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });
		expect(loginResponse.status).toBe(200);

		const impersonation = await request(server.app)
			.post('/api/auth/v1/impersonations')
			.set('authorization', `Bearer ${loginResponse.body.data.accessToken as string}`)
			.send({ login: targetUserInput.login });
		expect(impersonation.status).toBe(200);

		const end = await request(server.app)
			.delete('/api/auth/v1/impersonations?label=ended-via-query&browser=query-browser')
			.set('authorization', `Bearer ${impersonation.body.data.accessToken as string}`)
			.send({ label: 'should-not-be-used' });

		expect(end.status).toBe(200);
		expect(end.body.code).toBe(200);

		const stored = await store.getToken({
			refreshToken: end.body.data.refreshToken as string
		});
		expect(stored?.label).toBe('ended-via-query');
		expect(stored?.browser).toBe('query-browser');

		await store.close();
	});

	it('revokes the impersonation refresh token when impersonation ends', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.userStore.createUser(userInput);
		await store.userStore.createUser(targetUserInput);

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain,
			canImpersonate: () => true
		});
		server.authModule(authModule);
		server.api(authModule);

		const loginResponse = await request(server.app)
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });
		expect(loginResponse.status).toBe(200);

		const impersonation = await request(server.app)
			.post('/api/auth/v1/impersonations')
			.set('authorization', `Bearer ${loginResponse.body.data.accessToken as string}`)
			.send({ login: targetUserInput.login });
		expect(impersonation.status).toBe(200);

		const end = await request(server.app)
			.delete('/api/auth/v1/impersonations')
			.set('authorization', `Bearer ${impersonation.body.data.accessToken as string}`);
		expect(end.status).toBe(200);

		const refresh = await request(server.app)
			.post('/api/auth/v1/refresh')
			.send({
				refreshToken: impersonation.body.data.refreshToken as string
			});

		expect(refresh.status).toBe(401);
		expect(refresh.body.message).toBe('Invalid refresh token');

		await store.close();
	});

	it('applies rate-limit hook to login endpoint', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.userStore.createUser(userInput);

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain,
			rateLimit: ({ endpoint }) => {
				if (endpoint === 'login') {
					throw new ApiError({
						code: 429,
						message: 'Too many attempts'
					});
				}
			}
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app)
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });
		expect(response.status).toBe(429);
		expect(response.body.message).toBe('Too many attempts');

		await store.close();
	});

	it('applies rate-limit hook to passkey challenge endpoint', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.userStore.createUser(userInput);

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain,
			rateLimit: ({ endpoint }) => {
				if (endpoint === 'passkey-challenge') {
					throw new ApiError({
						code: 429,
						message: 'Passkey challenge throttled'
					});
				}
			}
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app)
			.post('/api/auth/v1/passkeys/challenge')
			.send({ action: 'authenticate', login: userInput.login });
		expect(response.status).toBe(429);
		expect(response.body.message).toBe('Passkey challenge throttled');

		await store.close();
	});

	it('applies rate-limit hook to oauth token endpoint', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.userStore.createUser(userInput);

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain,
			rateLimit: ({ endpoint }) => {
				if (endpoint === 'oauth-token') {
					throw new ApiError({
						code: 429,
						message: 'OAuth token throttled'
					});
				}
			}
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app)
			.post('/api/auth/v1/oauth2/token')
			.send({ grant_type: 'refresh_token' });
		expect(response.status).toBe(429);
		expect(response.body.message).toBe('OAuth token throttled');

		await store.close();
	});
});

describe('AuthModule route availability', () => {
	it('omits core auth routes when user storage is not configured', async () => {
		const storage = new BaseAuthAdapter();

		const server = new ApiServer(serverConfig).authStorage(storage);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app)
			.post('/api/auth/v1/login')
			.send({ login: userInput.login, password: userInput.password });

		expect(response.status).toBe(404);
	});

	it('omits core auth routes when only user methods are implemented and no token store is configured', async () => {
		interface DummyUser {
			id: string;
			login: string;
			password: string;
		}

		class UserOnlyStorage extends BaseAuthAdapter<DummyUser, Omit<DummyUser, 'password'>> {
			public override async getUser(identifier: string): Promise<DummyUser | null> {
				const id = String(identifier);
				if (id === 'sally' || id === '1') {
					return { id: '1', login: 'sally', password: 'pw' };
				}
				return null;
			}

			public override getUserPasswordHash(user: DummyUser): string {
				return user.password;
			}

			public override getUserId(user: DummyUser): string {
				return user.id;
			}

			public override filterUser(user: DummyUser): Omit<DummyUser, 'password'> {
				const { password: _password, ...safe } = user;
				void _password;
				return safe;
			}

			public override async verifyPassword(password: string, hash: string): Promise<boolean> {
				return password === hash;
			}
		}

		const storage = new UserOnlyStorage();

		const server = new ApiServer(serverConfig).authStorage(storage);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).post('/api/auth/v1/login').send({ login: 'sally', password: 'pw' });

		expect(response.status).toBe(404);
	});

	it('requires verifyClientSecret when OAuth clients have a secret configured', async () => {
		interface DummyUser {
			id: string;
			login: string;
			email: string;
			password: string;
		}

		class OAuthNoVerifyStorage extends BaseAuthAdapter<DummyUser, Omit<DummyUser, 'password'>> {
			public oauthStore = {};
			private readonly clients = new Map<string, { clientId: string; redirectUri: string }>();

			public override async getUser(identifier: string): Promise<DummyUser | null> {
				const id = String(identifier);
				if (id === 'sally' || id === '1') {
					return {
						id: '1',
						login: 'sally',
						email: 'sally@example.com',
						password: 'pw'
					};
				}
				return null;
			}

			public override getUserPasswordHash(user: DummyUser): string {
				return user.password;
			}

			public override getUserId(user: DummyUser): string {
				return user.id;
			}

			public override filterUser(user: DummyUser): Omit<DummyUser, 'password'> {
				const { password: _password, ...safe } = user;
				void _password;
				return safe;
			}

			public override async verifyPassword(password: string, hash: string): Promise<boolean> {
				return password === hash;
			}

			public override async storeToken(): Promise<void> {
				return;
			}

			public override async getToken(): Promise<null> {
				return null;
			}

			public override async deleteToken(): Promise<number> {
				return 0;
			}

			public override async getClient(clientId: string) {
				const client = this.clients.get(clientId);
				if (!client) {
					return null;
				}
				return {
					clientId: client.clientId,
					hasSecret: true,
					redirectUris: [client.redirectUri]
				};
			}

			public override async createAuthCode(request) {
				void request;
				return {
					code: 'any',
					clientId: 'oauth-app',
					userId: 1,
					redirectUri: 'https://app.example.com/callback',
					scope: [],
					expiresAt: new Date(Date.now() + 1000)
				};
			}

			public override async consumeAuthCode(): Promise<null> {
				return null;
			}

			public seedClient() {
				this.clients.set('oauth-app', {
					clientId: 'oauth-app',
					redirectUri: 'https://app.example.com/callback'
				});
			}
		}

		const storage = new OAuthNoVerifyStorage();
		storage.seedClient();

		const server = new ApiServer(serverConfig).authStorage(storage);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).post('/api/auth/v1/oauth2/token').send({
			grant_type: 'authorization_code',
			code: 'code',
			redirect_uri: 'https://app.example.com/callback',
			client_id: 'oauth-app',
			client_secret: 'top-secret'
		});

		expect(response.status).toBe(501);
		expect(response.body.message).toBe('OAuth client secret verification is not configured');
	});

	it('omits passkey routes when passkeys are disabled', async () => {
		const store = new MemAuthStore({ passkeys: false });
		await store.initialise();

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app)
			.post('/api/auth/v1/passkeys/challenge')
			.send({ action: 'register', login: 'any' });

		expect(response.status).toBe(404);

		await store.close();
	});

	it('omits oauth routes when an oauth store is not configured', async () => {
		class NoOAuthStorage extends BaseAuthAdapter {}
		const storage = new NoOAuthStorage();

		const server = new ApiServer(serverConfig).authStorage(storage);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).post('/api/auth/v1/oauth2/authorize').send({
			clientId: 'missing',
			redirectUri: 'https://example.com/callback'
		});

		expect(response.status).toBe(404);
	});

	it('exposes oauth routes when an oauth store is configured', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.userStore.createUser(userInput);

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).post('/api/auth/v1/oauth2/authorize').send({
			clientId: 'missing',
			redirectUri: 'https://example.com/callback',
			login: userInput.login,
			password: userInput.password
		});

		expect(response.status).not.toBe(404);

		await store.close();
	});

	it('requires PKCE when a public client requests an authorization code', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.userStore.createUser(userInput);
		await store.oauthStore.createClient({
			clientId: 'public-client',
			redirectUris: ['https://example.com/callback']
		});

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).post('/api/auth/v1/oauth2/authorize').send({
			clientId: 'public-client',
			redirectUri: 'https://example.com/callback',
			login: userInput.login,
			password: userInput.password
		});

		expect(response.status).toBe(400);
		expect(response.body.message).toBe('PKCE is required for public clients');

		await store.close();
	});

	it('authorizes and exchanges a public-client code using PKCE S256', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.userStore.createUser(userInput);
		await store.oauthStore.createClient({
			clientId: 'pkce-client',
			redirectUris: ['https://example.com/callback']
		});

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const verifier = 'a-public-client-verifier-that-is-long-enough-for-pkce';
		const challenge = createHash('sha256').update(verifier).digest('base64url');
		const authorization = await request(server.app).post('/api/auth/v1/oauth2/authorize').send({
			clientId: 'pkce-client',
			redirectUri: 'https://example.com/callback',
			login: userInput.login,
			password: userInput.password,
			codeChallenge: challenge,
			codeChallengeMethod: 'S256'
		});

		expect(authorization.status).toBe(200);
		const exchange = await request(server.app).post('/api/auth/v1/oauth2/token').send({
			grant_type: 'authorization_code',
			code: authorization.body.data.code as string,
			redirect_uri: 'https://example.com/callback',
			client_id: 'pkce-client',
			code_verifier: verifier
		});

		expect(exchange.status).toBe(200);
		expect(exchange.body.data.access_token).toEqual(expect.any(String));
		expect(exchange.body.data.refresh_token).toEqual(expect.any(String));

		await store.close();
	});

	it('rejects scopes that are not explicitly allowed for an OAuth client', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.userStore.createUser(userInput);
		await store.oauthStore.createClient({
			clientId: 'limited-client',
			redirectUris: ['https://example.com/callback'],
			scope: ['read']
		});
		await store.oauthStore.createClient({
			clientId: 'no-scope-client',
			redirectUris: ['https://example.com/callback']
		});

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).post('/api/auth/v1/oauth2/authorize').send({
			clientId: 'limited-client',
			redirectUri: 'https://example.com/callback',
			scope: 'read write',
			codeChallenge: createHash('sha256').update('verifier').digest('base64url'),
			codeChallengeMethod: 'S256',
			login: userInput.login,
			password: userInput.password
		});

		expect(response.status).toBe(400);
		expect(response.body.message).toBe('Requested scope is not permitted for this client');

		const noAllowlistResponse = await request(server.app).post('/api/auth/v1/oauth2/authorize').send({
			clientId: 'no-scope-client',
			redirectUri: 'https://example.com/callback',
			scope: 'write',
			codeChallenge: createHash('sha256').update('verifier').digest('base64url'),
			codeChallengeMethod: 'S256',
			login: userInput.login,
			password: userInput.password
		});

		expect(noAllowlistResponse.status).toBe(400);
		expect(noAllowlistResponse.body.message).toBe('Requested scope is not permitted for this client');

		await store.close();
	});

	it('accepts a refresh token in the OAuth authorize request body', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.oauthStore.createClient({
			clientId: 'refresh-auth-client',
			redirectUris: ['https://example.com/callback']
		});

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).post('/api/auth/v1/oauth2/authorize').send({
			clientId: 'refresh-auth-client',
			redirectUri: 'https://example.com/callback',
			codeChallenge: createHash('sha256').update('verifier').digest('base64url'),
			codeChallengeMethod: 'S256',
			refreshToken: 'invalid-refresh-token'
		});

		expect(response.status).toBe(401);
		expect(response.body.message).toBe('Invalid or expired refresh token');

		await store.close();
	});

	it('rejects legacy public-client authorization codes that have no PKCE challenge', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		const user = await store.userStore.createUser(userInput);
		await store.oauthStore.createClient({
			clientId: 'legacy-public-client',
			redirectUris: ['https://example.com/callback']
		});
		await store.oauthStore.createAuthCode({
			code: 'legacy-code',
			clientId: 'legacy-public-client',
			userId: store.getUserId(user),
			redirectUri: 'https://example.com/callback',
			expiresAt: new Date(Date.now() + 60_000)
		});

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).post('/api/auth/v1/oauth2/token').send({
			grant_type: 'authorization_code',
			code: 'legacy-code',
			redirect_uri: 'https://example.com/callback',
			client_id: 'legacy-public-client'
		});

		expect(response.status).toBe(400);
		expect(response.body.message).toBe('PKCE is required for public clients');

		await store.close();
	});

	it('rejects OAuth authorize requests using PKCE plain when allowInsecurePkcePlain is false', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.userStore.createUser(userInput);
		await store.oauthStore.createClient({
			clientId: 'plain-pkce-client',
			redirectUris: ['https://example.com/callback']
		});

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain,
			allowInsecurePkcePlain: false
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).post('/api/auth/v1/oauth2/authorize').send({
			clientId: 'plain-pkce-client',
			redirectUri: 'https://example.com/callback',
			login: userInput.login,
			password: userInput.password,
			codeChallenge: 'verifier-value',
			codeChallengeMethod: 'plain'
		});

		expect(response.status).toBe(400);
		expect(response.body.message).toBe('PKCE plain is not permitted');

		await store.close();
	});

	it('rejects OAuth authorize requests when codeChallengeMethod is missing', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.userStore.createUser(userInput);
		await store.oauthStore.createClient({
			clientId: 'missing-pkce-method-client',
			redirectUris: ['https://example.com/callback']
		});

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).post('/api/auth/v1/oauth2/authorize').send({
			clientId: 'missing-pkce-method-client',
			redirectUri: 'https://example.com/callback',
			login: userInput.login,
			password: userInput.password,
			codeChallenge: 'challenge-without-method'
		});

		expect(response.status).toBe(400);
		expect(response.body.message).toBe('codeChallengeMethod is required when codeChallenge is provided');

		await store.close();
	});

	it('rejects authorization-code exchange when a stored PKCE challenge has no method', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		const user = await store.userStore.createUser(userInput);
		await store.oauthStore.createClient({
			clientId: 'stale-pkce-client',
			redirectUris: ['https://example.com/callback']
		});
		await store.oauthStore.createAuthCode({
			code: 'stale-code',
			clientId: 'stale-pkce-client',
			userId: store.getUserId(user),
			redirectUri: 'https://example.com/callback',
			codeChallenge: 'stale-challenge',
			expiresAt: new Date(Date.now() + 60_000)
		});

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).post('/api/auth/v1/oauth2/token').send({
			grant_type: 'authorization_code',
			code: 'stale-code',
			redirect_uri: 'https://example.com/callback',
			client_id: 'stale-pkce-client',
			code_verifier: 'wrong-verifier'
		});

		expect(response.status).toBe(400);
		expect(response.body.message).toBe('Invalid or missing code_challenge_method');

		await store.close();
	});

	it('rejects unsupported OAuth token grant types', async () => {
		const store = new MemAuthStore();
		await store.initialise();
		await store.oauthStore.createClient({
			clientId: 'unsupported-grant-client',
			redirectUris: ['https://example.com/callback']
		});

		const server = new ApiServer(serverConfig).authStorage(store);
		const authModule = new AuthModule({
			defaultDomain: serverConfig.cookieDomain
		});
		server.authModule(authModule);
		server.api(authModule);

		const response = await request(server.app).post('/api/auth/v1/oauth2/token').send({
			grant_type: 'device_code',
			client_id: 'unsupported-grant-client'
		});

		expect(response.status).toBe(400);
		expect(response.body.message).toBe('Validation failed');
		expect(response.body.errors).toHaveProperty('grant_type');

		await store.close();
	});
});
