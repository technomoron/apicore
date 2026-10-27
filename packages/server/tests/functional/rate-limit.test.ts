import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiModule, type ApiRoute } from '../../src/apicore-server';
import { TestServer, signToken } from '../helpers/test-server';

import type { RateLimitConfig } from '../../src/index';

// Mount routes exercising independent authentication and quota choices.
class QuotaModule extends ApiModule {
	// Register quotas and public/authenticated handlers in the real Fastify pipeline.
	public override defineRoutes(): ApiRoute[] {
		return [
			{ method: 'get', path: '/plain', auth: { type: 'none', req: 'any' }, handler: async () => [200] },
			{
				method: 'get',
				path: '/off',
				rateLimit: false,
				auth: { type: 'none', req: 'any' },
				handler: async () => [200]
			},
			{
				method: 'get',
				path: '/ip',
				rateLimit: 'route',
				auth: { type: 'none', req: 'any' },
				handler: async () => [200]
			},
			{
				method: 'get',
				path: '/user',
				rateLimit: 'user',
				auth: { type: 'yes', req: 'any' },
				handler: async () => [200]
			},
			{
				method: 'get',
				path: '/anonymous',
				rateLimit: 'user',
				auth: { type: 'none', req: 'any' },
				handler: async () => [200]
			}
		];
	}
}

const policies: NonNullable<RateLimitConfig['policies']> = {
	global: { limit: 2, windowMs: 60_000, identity: 'ip' },
	route: { limit: 1, windowMs: 60_000, identity: 'ip' },
	user: { limit: 1, windowMs: 60_000, identity: 'user' }
};
const servers: TestServer[] = [];

// Create a server with quota routes and automatic cleanup.
function createQuotaServer(config: ConstructorParameters<typeof TestServer>[0] = {}): TestServer {
	const server = new TestServer({ rateLimits: { policies }, ...config });
	server.api(new QuotaModule({ namespace: '/quota' }));
	servers.push(server);
	return server;
}

afterEach(async () => {
	await Promise.all(servers.splice(0).map((server) => server.fastify.close()));
	vi.restoreAllMocks();
});

describe('API quotas', () => {
	it('applies global quotas to plain routes and rateLimit:false before authentication', async () => {
		const server = createQuotaServer({ rateLimits: { policies, global: 'global' } });
		const authenticate = vi.spyOn(server, 'authenticate');
		expect((await server.fastify.inject('/api/quota/plain')).statusCode).toBe(200);
		expect((await server.fastify.inject('/api/quota/off')).statusCode).toBe(200);
		const denied = await server.fastify.inject('/api/quota/user');
		expect(denied.statusCode).toBe(429);
		expect(denied.json().data.retryAfterSec).toBeGreaterThan(0);
		expect(authenticate).toHaveBeenCalledTimes(2);
	});

	it('charges failed authentication to the global quota', async () => {
		const server = createQuotaServer({
			rateLimits: { policies: { ...policies, global: { ...policies.global, limit: 1 } }, global: 'global' }
		});
		expect((await server.fastify.inject('/api/quota/user')).statusCode).toBe(401);
		expect((await server.fastify.inject('/api/quota/user')).statusCode).toBe(429);
	});

	it('rejects unknown route policies at mount time', () => {
		const server = new TestServer();
		servers.push(server);
		expect(() => server.api(new QuotaModule())).toThrow('Unknown rate limit policy');
	});

	it('enforces a route quota only on routes selecting it', async () => {
		const server = createQuotaServer();
		expect((await server.fastify.inject('/api/quota/ip')).statusCode).toBe(200);
		expect((await server.fastify.inject('/api/quota/ip')).statusCode).toBe(429);
		expect((await server.fastify.inject('/api/quota/off')).statusCode).toBe(200);
		expect((await server.fastify.inject('/api/quota/plain')).statusCode).toBe(200);
	});

	it('runs user quotas after authentication and uses real identity during impersonation', async () => {
		const server = createQuotaServer();
		const consume = vi.spyOn(server.rateLimiter, 'consume');
		expect((await server.fastify.inject('/api/quota/user')).statusCode).toBe(401);
		expect(consume).not.toHaveBeenCalled();
		const token = signToken(server, { uid: 'effective-a', ruid: 'real-user', role: 'any' });
		expect((await server.fastify.inject({ url: '/api/quota/user', cookies: { dat: token } })).statusCode).toBe(200);
		expect(consume).toHaveBeenCalledWith('user', 'real-user');
		const other = signToken(server, { uid: 'effective-b', ruid: 'real-user', role: 'any' });
		expect((await server.fastify.inject({ url: '/api/quota/user', cookies: { dat: other } })).statusCode).toBe(429);
	});

	it('fails closed when an identity is missing', async () => {
		const server = createQuotaServer();
		expect((await server.fastify.inject('/api/quota/anonymous')).statusCode).toBe(401);
	});

	it('fails closed on backend errors and leaves native Fastify routes outside quotas', async () => {
		const server = createQuotaServer({
			rateLimits: {
				policies,
				global: 'global',
				store: {
					consume: async () => {
						throw new Error('backend unavailable');
					}
				}
			}
		});
		server.fastify.get('/native', async () => ({ ok: true }));
		const denied = await server.fastify.inject('/api/quota/plain');
		expect(denied.statusCode).toBe(500);
		expect(denied.json().message).toBe('Internal server error');
		expect((await server.fastify.inject('/native')).statusCode).toBe(200);
	});

	it.each([
		{ trustProxy: false, allowed: false },
		{ trustProxy: 1, allowed: false },
		{ trustProxy: 2, allowed: true }
	])('resolves trusted IPs with trustProxy=$trustProxy', async ({ trustProxy, allowed }) => {
		const server = createQuotaServer({ trustProxy });
		const first = await server.fastify.inject({
			url: '/api/quota/ip',
			remoteAddress: '10.0.0.1',
			headers: { 'x-forwarded-for': '192.0.2.1, 10.0.0.2' }
		});
		const second = await server.fastify.inject({
			url: '/api/quota/ip',
			remoteAddress: '10.0.0.1',
			headers: { 'x-forwarded-for': '192.0.2.2, 10.0.0.2' }
		});
		expect(first.statusCode).toBe(200);
		expect(second.statusCode).toBe(allowed ? 200 : 429);
	});

	it('exposes an independent audit sink without automatic auth events', async () => {
		const sink = vi.fn();
		const server = createQuotaServer({ securityEventSink: sink });
		await server.fastify.inject('/api/quota/user');
		expect(sink).not.toHaveBeenCalled();
		await server.securityEvents.report('auth.login.failed', { ip: '192.0.2.1' });
		expect(sink).toHaveBeenCalledWith(expect.objectContaining({ event: 'auth.login.failed', ip: '192.0.2.1' }));
	});
});
