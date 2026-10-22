import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { describe, expect, it } from 'vitest';

import { ApiServer } from '../../../src/apicore-server.js';
import { MemAuthStore } from '../../../src/auth-api/mem-auth-store.js';
import { OAuthAuthorizationServer } from '../../../src/oauth/authorization-server.js';
import { OAuthPasswordLogin } from '../../../src/oauth/password-login.js';
import { verifyTotp } from '../../../src/oauth/totp.js';
import { JsonTokenStore } from '../../../src/token/json.js';

describe('OAuth login and persistent sessions', () => {
	it('verifies RFC 6238 codes and rejects replay', () => {
		const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
		expect(verifyTotp(secret, '94287082', { time: 59000, digits: 8, window: 0 })).toBe(1);
		expect(verifyTotp(secret, '94287082', { time: 59000, digits: 8, after: 1 })).toBeNull();
		expect(verifyTotp(secret, '00000000', { time: 59000, digits: 8 })).toBeNull();
	});
	it('persists independent sessions and revocation across store restarts', async () => {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'oauth-sessions-'));
		try {
			const file = path.join(directory, 'sessions.json');
			const store = new JsonTokenStore(file);
			for (const id of ['a', 'b'])
				await store.save({
					userId: 'user',
					clientId: 'client',
					accessToken: 'access-' + id,
					refreshToken: 'refresh-' + id,
					expires: new Date(Date.now() + 60000)
				});
			const restarted = new JsonTokenStore(file);
			expect(await restarted.list('user')).toHaveLength(2);
			await restarted.delete({ refreshToken: 'refresh-a' });
			expect(await store.get({ refreshToken: 'refresh-a' })).toBeNull();
			expect(await store.get({ refreshToken: 'refresh-b' })).not.toBeNull();
			if (process.platform !== 'win32') expect(fs.statSync(file).mode & 0o777).toBe(0o600);
		} finally {
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});
	it('requires CSRF, password, second factor and consent before issuing an authorization code', async () => {
		const storage = new MemAuthStore({ bcryptRounds: 4, passkeys: false });
		await storage.userStore.createUser({ login: 'sally', email: 'sally@example.com', password: 'secret' });
		await storage.oauthStore.createClient({
			clientId: 'desktop',
			redirectUris: ['http://127.0.0.1:8123/callback'],
			scope: ['read']
		});
		const api = new ApiServer({ authApi: false }).authStorage(storage);
		const login = new OAuthPasswordLogin(api, {
			issuer: 'https://auth.example/oauth',
			allow: () => true,
			verifySecondFactor: (_user, code) => code === '123456'
		}).register();
		new OAuthAuthorizationServer(api, {
			issuer: 'https://auth.example/oauth',
			resources: ['https://mcp.example/mcp'],
			scopes: ['read'],
			accessSecret: 'access'.repeat(8),
			refreshSecret: 'refresh'.repeat(8),
			authorize: login.authorize
		}).register();
		try {
			const verifier = 'a'.repeat(43);
			const url =
				'/oauth/authorize?' +
				new URLSearchParams({
					client_id: 'desktop',
					redirect_uri: 'http://127.0.0.1:8123/callback',
					response_type: 'code',
					resource: 'https://mcp.example/mcp',
					scope: 'read',
					code_challenge: createHash('sha256').update(verifier).digest('base64url'),
					code_challenge_method: 'S256'
				});
			const form = await api.fastify.inject({ url });
			expect(form.statusCode).toBe(200);
			expect(form.body).toContain('Sign in and allow access');
			const cookie = (form.headers['set-cookie'] as string).split(';')[0];
			const request = /name="request" value="([^"]+)"/.exec(form.body)![1];
			const csrf = /name="csrf" value="([^"]+)"/.exec(form.body)![1];
			const submit = (changes = {}) =>
				api.fastify.inject({
					method: 'POST',
					url: '/oauth/login',
					headers: {
						cookie,
						'content-type': 'application/x-www-form-urlencoded',
						origin: 'https://auth.example'
					},
					payload: new URLSearchParams({
						request,
						csrf,
						login: 'sally',
						password: 'secret',
						code: '123456',
						...changes
					}).toString()
				});
			expect((await submit({ csrf: 'wrong' })).statusCode).toBe(403);
			expect((await submit({ password: 'wrong' })).statusCode).toBe(401);
			expect((await submit({ code: 'wrong' })).statusCode).toBe(401);
			const accepted = await submit();
			expect(accepted.statusCode).toBe(302);
			const cookies = accepted.headers['set-cookie'] as string[];
			const approval = cookies.find((value) => value.includes('_approved='))!.split(';')[0];
			const authorized = await api.fastify.inject({ url, headers: { cookie: approval } });
			expect(authorized.statusCode).toBe(302);
			expect(new URL(authorized.headers.location!).searchParams.get('code')).toBeTruthy();
			expect((await api.fastify.inject({ url, headers: { cookie: approval } })).statusCode).toBe(200);
		} finally {
			await api.fastify.close();
			await storage.close();
		}
	});
});
