import { createHash } from 'node:crypto';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiServer } from '../../../src/apicore-server.js';
import { MemAuthStore } from '../../../src/auth-api/mem-auth-store.js';
import { OAuthAuthorizationServer, OAuthProtocolError } from '../../../src/oauth/authorization-server.js';

import type { OAuthAuthorizationServerOptions } from '../../../src/oauth/authorization-server.js';

const resource = 'https://api.example.com';
const secondResource = 'https://second.example.com';
const issuer = 'https://auth.example.com/oauth';
const redirectUri = 'http://127.0.0.1:8123/callback';
const verifier = 'a'.repeat(43);
const challenge = createHash('sha256').update(verifier).digest('base64url');
const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
	for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

async function harness(overrides: Partial<OAuthAuthorizationServerOptions> = {}) {
	const store = new MemAuthStore({ bcryptRounds: 4, passkeys: false });
	await store.initialise();
	const user = await store.userStore.createUser({ login: 'sally', email: 'sally@example.com', password: 'secret' });
	const server = new ApiServer({ swaggerEnabled: true }).authStorage(store);
	cleanups.push(async () => {
		await server.fastify.close();
		await store.close();
	});
	await store.oauthStore.createClient({
		clientId: 'desktop',
		redirectUris: [redirectUri],
		scope: ['read', 'write']
	});
	const authorize = vi.fn(() => ({ userId: store.getUserId(user) }));
	const provider = new OAuthAuthorizationServer(server, {
		issuer,
		resources: [resource, secondResource],
		scopes: ['read', 'write'],
		accessSecret: 'access'.repeat(8),
		refreshSecret: 'refresh'.repeat(8),
		authorize,
		...overrides
	}).register();
	await server.fastify.ready();
	const authorizationUrl = (changes: Record<string, string> = {}) => {
		const params = new URLSearchParams({
			client_id: 'desktop',
			redirect_uri: redirectUri,
			response_type: 'code',
			code_challenge: challenge,
			code_challenge_method: 'S256',
			scope: 'read write',
			resource,
			state: 'exact +& state',
			...changes
		});
		return '/oauth/authorize?' + params;
	};
	const authorizeCode = async (changes: Record<string, string> = {}) => {
		const response = await server.fastify.inject({ method: 'GET', url: authorizationUrl(changes) });
		expect(response.statusCode).toBe(302);
		const target = new URL(response.headers.location as string);
		expect(target.searchParams.get('error')).toBeNull();
		return target.searchParams.get('code')!;
	};
	const exchange = (body: Record<string, string>) =>
		server.fastify.inject({
			method: 'POST',
			url: '/oauth/token',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			payload: new URLSearchParams({ client_id: 'desktop', ...body }).toString()
		});
	const tokens = async () => {
		const code = await authorizeCode();
		const response = await exchange({
			grant_type: 'authorization_code',
			code,
			redirect_uri: redirectUri,
			code_verifier: verifier,
			resource
		});
		expect(response.statusCode).toBe(200);
		return response.json() as { access_token: string; refresh_token: string; scope: string };
	};
	return { server, store, provider, authorize, authorizationUrl, authorizeCode, exchange, tokens };
}

describe('standard OAuth authorization server', () => {
	it('issues independent service grants and reapplies policy before issuance', async () => {
		let permitted = true;
		const { store, exchange, provider } = await harness({ serviceAccounts: { service: '1' }, validateGrant: () => permitted });
		await store.oauthStore.createClient({ clientId: 'service', clientSecret: 'service-secret', redirectUris: [], scope: ['read'] });
		const grant = () => exchange({ grant_type: 'client_credentials', client_id: 'service', client_secret: 'service-secret', scope: 'read', resource });
		const first = await grant();
		const second = await grant();
		expect(first.statusCode).toBe(200);
		expect(second.statusCode).toBe(200);
		expect(first.json().refresh_token).toBeUndefined();
		expect((await provider.verifyAccessToken(first.json().access_token, resource)).sub).toBe('1');
		expect((await provider.verifyAccessToken(second.json().access_token, resource)).sub).toBe('1');
		permitted = false;
		expect((await grant()).json().error).toBe('invalid_grant');
	});
	it('publishes issuer-specific metadata without using untrusted Host headers', async () => {
		const { server, provider } = await harness();
		const response = await server.fastify.inject({
			url: '/.well-known/oauth-authorization-server/oauth',
			headers: { host: 'attacker.example' }
		});
		expect(response.json()).toMatchObject({
			issuer,
			authorization_endpoint: issuer + '/authorize',
			token_endpoint: issuer + '/token',
			response_types_supported: ['code'],
			code_challenge_methods_supported: ['S256'],
			authorization_response_iss_parameter_supported: true
		});
		expect(response.json()).not.toHaveProperty('data');
		expect(provider.resourceMetadata(resource)).toMatchObject({
			resource,
			authorization_servers: [issuer],
			bearer_methods_supported: ['header']
		});
		expect(() => provider.resourceMetadata('https://unknown.example')).toThrow('Unknown OAuth resource');
	});

	it('redirects with the exact state and exchanges a code for resource-bound tokens', async () => {
		const env = await harness();
		const response = await env.server.fastify.inject({ url: env.authorizationUrl() });
		expect(response.statusCode).toBe(302);
		const redirect = new URL(response.headers.location as string);
		expect(redirect.searchParams.get('state')).toBe('exact +& state');
		expect(redirect.searchParams.get('iss')).toBe(issuer);
		expect(env.authorize.mock.calls[0][0]).toMatchObject({ resources: [resource], scopes: ['read', 'write'] });
		const tokens = await env.tokens();
		const claims = await env.provider.verifyAccessToken(tokens.access_token, resource, ['read']);
		expect(claims).toMatchObject({ iss: issuer, aud: [resource], client_id: 'desktop', scope: 'read write' });
		await expect(env.provider.verifyAccessToken(tokens.access_token, secondResource)).rejects.toMatchObject({
			error: 'invalid_token'
		});
		await expect(env.provider.verifyAccessToken(tokens.access_token, resource, ['admin'])).rejects.toMatchObject({
			error: 'insufficient_scope'
		});
		await expect(env.provider.verifyAccessToken(tokens.refresh_token, resource)).rejects.toMatchObject({
			error: 'invalid_token'
		});
	});

	it('does not redirect or invoke login for an unknown client or redirect URI', async () => {
		const env = await harness();
		for (const changes of [{ client_id: 'unknown' }, { redirect_uri: 'https://attacker.example/callback' }]) {
			const response = await env.server.fastify.inject({ url: env.authorizationUrl(changes) });
			expect(response.statusCode).toBe(400);
			expect(response.headers.location).toBeUndefined();
		}
		expect(env.authorize).not.toHaveBeenCalled();
	});

	it('rejects duplicate parameters, unsupported flows, bad scopes and missing S256 before login', async () => {
		const env = await harness();
		for (const changes of [
			{ code_challenge_method: 'plain' },
			{ code_challenge: '' },
			{ response_type: 'token' },
			{ scope: 'admin' },
			{ resource: 'https://attacker.example' }
		]) {
			const response = await env.server.fastify.inject({ url: env.authorizationUrl(changes) });
			expect(new URL(response.headers.location as string).searchParams.has('error')).toBe(true);
		}
		const duplicate = await env.server.fastify.inject({ url: env.authorizationUrl() + '&client_id=second' });
		expect(duplicate.statusCode).toBe(400);
		expect(duplicate.headers.location).toBeUndefined();
		expect(env.authorize).not.toHaveBeenCalled();
	});

	it('supports explicit consent refusal and application-managed login responses', async () => {
		const denied = await harness({ authorize: () => false });
		const response = await denied.server.fastify.inject({ url: denied.authorizationUrl() });
		expect(new URL(response.headers.location as string).searchParams.get('error')).toBe('access_denied');
		const login = await harness({
			authorize: ({ reply }) => {
				reply.type('text/html').send('<p>Login required</p>');
			}
		});
		const page = await login.server.fastify.inject({ url: login.authorizationUrl() });
		expect(page.statusCode).toBe(200);
		expect(page.body).toContain('Login required');
		expect(page.headers.location).toBeUndefined();
	});

	it('requires the verifier, permits only the granted resource and consumes codes once', async () => {
		const env = await harness();
		const body = { grant_type: 'authorization_code', redirect_uri: redirectUri, code_verifier: verifier };
		const wrongProof = await env.exchange({
			...body,
			code: await env.authorizeCode(),
			code_verifier: 'b'.repeat(43)
		});
		expect(wrongProof.json().error).toBe('invalid_grant');
		const wrongResource = await env.exchange({
			...body,
			code: await env.authorizeCode(),
			resource: secondResource
		});
		expect(wrongResource.json().error).toBe('invalid_target');
		const code = await env.authorizeCode();
		expect((await env.exchange({ ...body, code })).statusCode).toBe(200);
		const replay = await env.exchange({ ...body, code });
		expect(replay.json().error).toBe('invalid_grant');
		expect(replay.headers['cache-control']).toBe('no-store');
	});

	it('rotates refresh tokens, refuses replay and escalation, and retains grant expiry', async () => {
		const env = await harness();
		const original = await env.tokens();
		const before = env.server.jwtDecode<{ exp: number }>(original.refresh_token).data!;
		const escalate = await env.exchange({
			grant_type: 'refresh_token',
			refresh_token: original.refresh_token,
			scope: 'admin'
		});
		expect(escalate.json().error).toBe('invalid_scope');
		const target = await env.exchange({
			grant_type: 'refresh_token',
			refresh_token: original.refresh_token,
			resource: secondResource
		});
		expect(target.json().error).toBe('invalid_target');
		const response = await env.exchange({
			grant_type: 'refresh_token',
			refresh_token: original.refresh_token,
			scope: 'read'
		});
		expect(response.statusCode).toBe(200);
		const rotated = response.json();
		expect(rotated.scope).toBe('read');
		expect(env.server.jwtDecode<{ exp: number }>(rotated.refresh_token).data!.exp).toBe(before.exp);
		await expect(env.provider.verifyAccessToken(original.access_token, resource)).rejects.toMatchObject({
			error: 'invalid_token'
		});
		await expect(env.provider.verifyAccessToken(rotated.access_token, resource, ['write'])).rejects.toMatchObject({
			error: 'insufficient_scope'
		});
		expect(
			(await env.exchange({ grant_type: 'refresh_token', refresh_token: original.refresh_token })).json().error
		).toBe('invalid_grant');
	});

	it('allows only one concurrent refresh exchange to succeed', async () => {
		const env = await harness();
		const pair = await env.tokens();
		const results = await Promise.all(
			[1, 2].map(() =>
				env.exchange({
					grant_type: 'refresh_token',
					refresh_token: pair.refresh_token
				})
			)
		);
		expect(results.map((result) => result.statusCode).sort()).toEqual([200, 400]);
	});

	it('checks confidential clients and accepts HTTP Basic client authentication', async () => {
		const env = await harness();
		await env.store.oauthStore.createClient({
			clientId: 'confidential',
			clientSecret: 'client secret',
			redirectUris: [redirectUri],
			scope: ['read']
		});
		const code = await env.authorizeCode({ client_id: 'confidential', scope: 'read' });
		const params = new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			redirect_uri: redirectUri,
			code_verifier: verifier
		});
		const basic = Buffer.from('confidential:client+secret').toString('base64');
		const denied = await env.exchange({
			...Object.fromEntries(params),
			client_id: 'confidential',
			client_secret: 'wrong'
		});
		expect(denied.statusCode).toBe(401);
		expect(denied.json().error).toBe('invalid_client');
		const accepted = await env.server.fastify.inject({
			method: 'POST',
			url: '/oauth/token',
			headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: 'Basic ' + basic },
			payload: params.toString()
		});
		expect(accepted.statusCode).toBe(200);
	});

	it('returns standard OAuth errors for malformed form bodies and hides internal failures', async () => {
		const env = await harness();
		const json = await env.server.fastify.inject({
			method: 'POST',
			url: '/oauth/token',
			payload: { grant_type: 'refresh_token' }
		});
		expect(json.json().error).toBe('invalid_request');
		const duplicate = await env.server.fastify.inject({
			method: 'POST',
			url: '/oauth/token',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			payload: 'grant_type=refresh_token&client_id=desktop&client_id=other'
		});
		expect(duplicate.json().error).toBe('invalid_request');
		const failure = await harness({
			rateLimit: () => {
				throw new Error('private backend details');
			}
		});
		const response = await failure.exchange({ grant_type: 'refresh_token' });
		expect(response.statusCode).toBe(500);
		expect(response.body).not.toContain('private backend');
		expect(response.json().error).toBe('server_error');
	});

	it('accepts repeated resource indicators and only narrows the authorization grant', async () => {
		const env = await harness();
		const response = await env.server.fastify.inject({
			url: env.authorizationUrl() + '&resource=' + encodeURIComponent(secondResource)
		});
		const code = new URL(response.headers.location as string).searchParams.get('code')!;
		const exchanged = await env.exchange({
			grant_type: 'authorization_code',
			code,
			redirect_uri: redirectUri,
			code_verifier: verifier,
			resource: secondResource
		});
		expect(exchanged.statusCode).toBe(200);
		const pair = exchanged.json();
		expect((await env.provider.verifyAccessToken(pair.access_token, secondResource)).aud).toEqual([secondResource]);
		await expect(env.provider.verifyAccessToken(pair.access_token, resource)).rejects.toMatchObject({
			error: 'invalid_token'
		});
		const widened = await env.exchange({
			grant_type: 'refresh_token',
			refresh_token: pair.refresh_token,
			resource
		});
		expect(widened.json().error).toBe('invalid_target');
	});

	it('rejects expired and revoked tokens and access tokens presented as refresh tokens', async () => {
		const env = await harness({ accessExpiry: 1, refreshExpiry: 2 });
		const pair = await env.tokens();
		const wrongUse = await env.exchange({ grant_type: 'refresh_token', refresh_token: pair.access_token });
		expect(wrongUse.json().error).toBe('invalid_grant');
		const realNow = Date.now;
		vi.spyOn(Date, 'now').mockReturnValue(realNow() + 3000);
		try {
			await expect(env.provider.verifyAccessToken(pair.access_token, resource)).rejects.toMatchObject({
				error: 'invalid_token'
			});
			const expired = await env.exchange({ grant_type: 'refresh_token', refresh_token: pair.refresh_token });
			expect(expired.json().error).toBe('invalid_grant');
		} finally {
			vi.restoreAllMocks();
		}
		const active = await env.tokens();
		await env.server.deleteToken({ refreshToken: active.refresh_token });
		await expect(env.provider.verifyAccessToken(active.access_token, resource)).rejects.toMatchObject({
			error: 'invalid_token'
		});
	});

	it('documents optional endpoints at their configured runtime paths', async () => {
		const env = await harness({ issuer: 'https://auth.example.com/tenant/team' });
		const response = await env.server.fastify.inject({ url: '/api/swagger' });
		expect(response.statusCode).toBe(200);
		const paths = response.json().paths;
		expect(paths).toHaveProperty('/tenant/team/authorize');
		expect(paths).toHaveProperty('/tenant/team/token');
		expect(paths).toHaveProperty('/.well-known/oauth-authorization-server/tenant/team');
		expect(paths).not.toHaveProperty('/oauth/token');
	});

	it('is opt-in and validates HTTPS, key separation and resource configuration', async () => {
		const server = new ApiServer();
		cleanups.push(() => server.fastify.close());
		expect((await server.fastify.inject({ url: '/.well-known/oauth-authorization-server/oauth' })).statusCode).toBe(
			404
		);
		const options: OAuthAuthorizationServerOptions = {
			issuer,
			resources: [resource],
			accessSecret: 'a'.repeat(40),
			refreshSecret: 'r'.repeat(40),
			authorize: () => false
		};
		expect(() => new OAuthAuthorizationServer(server, { ...options, issuer: 'http://auth.example.com' })).toThrow(
			'HTTPS'
		);
		expect(() => new OAuthAuthorizationServer(server, { ...options, resources: [resource + '#fragment'] })).toThrow(
			'resources'
		);
		expect(() => new OAuthAuthorizationServer(server, { ...options, refreshSecret: options.accessSecret })).toThrow(
			'distinct'
		);
		expect(new OAuthProtocolError('access_denied', 'Declined').error).toBe('access_denied');
	});
});
