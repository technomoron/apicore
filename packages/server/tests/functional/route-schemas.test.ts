import request from 'supertest';
import { describe, expect, it } from 'vitest';

import { ApiModule, type ApiRoute } from '../../src/apicore-server';
import { createServer } from '../helpers/test-server';

class ContractModule extends ApiModule {
	public static override defaultNamespace = '/contracts';

	public override defineRoutes(): ApiRoute[] {
		return [
			{
				method: 'get',
				path: '/header-guarded',
				auth: { type: 'none', req: 'any' },
				schema: {
					headers: {
						type: 'object',
						required: ['x-contract'],
						properties: {
							'x-contract': { type: 'string', const: 'ok' }
						},
						additionalProperties: true
					}
				},
				handler: async () => [200, { ok: true }]
			},
			{
				method: 'post',
				path: '/body-default',
				auth: { type: 'none', req: 'any' },
				schema: {
					body: {
						type: 'object',
						required: ['name'],
						properties: {
							name: { type: 'string' }
						}
					}
				},
				handler: async ({ req }) => [200, req.body ?? null]
			},
			{
				method: 'post',
				path: '/body-opt-in',
				auth: { type: 'none', req: 'any' },
				strictProps: false,
				schema: {
					body: {
						type: 'object',
						required: ['name'],
						properties: {
							name: { type: 'string' }
						}
					}
				},
				handler: async ({ req }) => [200, req.body ?? null]
			},
			{
				method: 'post',
				path: '/body-explicit',
				auth: { type: 'none', req: 'any' },
				strictProps: false,
				schema: {
					body: {
						type: 'object',
						required: ['name'],
						properties: {
							name: { type: 'string' }
						},
						additionalProperties: false
					}
				},
				handler: async ({ req }) => [200, req.body ?? null]
			}
		];
	}
}

describe('Route schemas', () => {
	it('lets extension modules pass full Fastify schemas such as headers', async () => {
		const server = createServer();
		server.api(new ContractModule());

		const denied = await request(server.app).get('/api/contracts/header-guarded');
		expect(denied.status).toBe(400);
		expect(denied.body.message).toBe('Validation failed');
		expect(denied.body.errors).toHaveProperty('x-contract');

		const allowed = await request(server.app).get('/api/contracts/header-guarded').set('x-contract', 'ok');
		expect(allowed.status).toBe(200);
		expect(allowed.body.data).toEqual({ ok: true });
	});

	it('defaults additionalProperties to false for body schemas', async () => {
		const server = createServer();
		server.api(new ContractModule());

		const response = await request(server.app)
			.post('/api/contracts/body-default')
			.send({ name: 'demo', extra: true });

		expect(response.status).toBe(400);
		expect(response.body.message).toBe('Validation failed');
		expect(response.body.errors).toHaveProperty('extra');
	});

	it('lets a route opt out of strictProps', async () => {
		const server = createServer();
		server.api(new ContractModule());

		const response = await request(server.app)
			.post('/api/contracts/body-opt-in')
			.send({ name: 'demo', extra: true });

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ name: 'demo', extra: true });
	});

	it('lets explicit schema additionalProperties override the route default', async () => {
		const server = createServer();
		server.api(new ContractModule());

		const response = await request(server.app)
			.post('/api/contracts/body-explicit')
			.send({ name: 'demo', extra: true });

		expect(response.status).toBe(400);
		expect(response.body.message).toBe('Validation failed');
		expect(response.body.errors).toHaveProperty('extra');
	});
});
