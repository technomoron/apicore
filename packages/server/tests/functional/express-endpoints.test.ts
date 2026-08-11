import request from 'supertest';
import { describe, it, expect } from 'vitest';

import { createServer, signToken } from '../helpers/test-server';

import type { ExpressApiRequest, _ApiReply } from '../../src/apicore-server';

describe('Custom Express endpoints', () => {
	it('supports PATCH routes registered via ApiModule', async () => {
		const server = createServer();
		const response = await request(server.app).patch('/api/example/patchable').send({ x: 1 });
		expect(response.status).toBe(200);
		expect(response.body).toEqual({
			success: true,
			code: 200,
			message: 'Success',
			data: { patched: true, body: { x: 1 } },
			errors: {}
		});
	});

	it('mounts custom endpoints under apiBasePath without being intercepted by the API 404 handler', async () => {
		const server = createServer();

		server.useExpress('/api/custom/ping', (_req, res) => {
			res.status(200).json({ ok: true });
		});

		const response = await request(server.app).get('/api/custom/ping');
		expect(response.status).toBe(200);
		expect(response.body).toEqual({ ok: true });
	});

	it('supports optional authentication via expressAuth', async () => {
		const server = createServer();

		server.useExpress(
			'/api/custom/optional',
			server.expressAuth({ type: 'maybe', req: 'any' }),
			(req: ExpressApiRequest, res: _ApiReply) => {
				const tokenData = req.apiReq?.tokenData ?? null;
				res.status(200).json({
					authenticated: Boolean(tokenData),
					uid: tokenData?.uid ?? null
				});
			}
		);

		const anon = await request(server.app).get('/api/custom/optional');
		expect(anon.status).toBe(200);
		expect(anon.body).toEqual({ authenticated: false, uid: null });

		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const authed = await request(server.app).get('/api/custom/optional').set('Authorization', `Bearer ${token}`);
		expect(authed.status).toBe(200);
		expect(authed.body).toEqual({ authenticated: true, uid: 'user-1' });
	});

	it('enforces required auth and formats errors via expressErrorHandler', async () => {
		const server = createServer();

		server.useExpress(
			'/api/custom/secure',
			server.expressAuth({ type: 'yes', req: 'any' }),
			(req: ExpressApiRequest, res: _ApiReply) => {
				res.status(200).json({
					uid: req.apiReq?.tokenData?.uid ?? null
				});
			}
		);
		server.useExpress(server.expressErrorHandler());

		const denied = await request(server.app).get('/api/custom/secure');
		expect(denied.status).toBe(401);
		expect(denied.body).toEqual({
			success: false,
			code: 401,
			message: 'Authorization token is required (Bearer/cookie)',
			data: null,
			errors: {}
		});

		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const allowed = await request(server.app).get('/api/custom/secure').set('Authorization', `Bearer ${token}`);
		expect(allowed.status).toBe(200);
		expect(allowed.body).toEqual({ uid: 'user-1' });
	});

	it('enforces authorization classes for custom endpoints', async () => {
		const server = createServer();

		server.useExpress(
			'/api/custom/admin',
			server.expressAuth({ type: 'yes', req: 'admin' }),
			(req: ExpressApiRequest, res: _ApiReply) => {
				res.status(200).json({
					role: req.apiReq?.tokenData?.role ?? null
				});
			}
		);
		server.useExpress(server.expressErrorHandler());

		const userToken = signToken(server, { uid: 'user-1', role: 'any' });
		const denied = await request(server.app).get('/api/custom/admin').set('Authorization', `Bearer ${userToken}`);
		expect(denied.status).toBe(403);
		expect(denied.body).toEqual({
			success: false,
			code: 403,
			message: 'Forbidden',
			data: null,
			errors: {}
		});

		const adminToken = signToken(server, { uid: 'admin-1', role: 'admin' });
		const allowed = await request(server.app).get('/api/custom/admin').set('Authorization', `Bearer ${adminToken}`);
		expect(allowed.status).toBe(200);
		expect(allowed.body).toEqual({ role: 'admin' });
	});

	it('supports API key authentication for custom endpoints', async () => {
		const server = createServer();

		server.useExpress(
			'/api/custom/apikey',
			server.expressAuth({ type: 'apikey', req: 'any' }),
			(req: ExpressApiRequest, res: _ApiReply) => {
				res.status(200).json({
					uid: req.apiReq?.tokenData?.uid ?? null,
					token: req.apiReq?.token ?? null
				});
			}
		);
		server.useExpress(server.expressErrorHandler());

		const missing = await request(server.app).get('/api/custom/apikey');
		expect(missing.status).toBe(401);
		expect(missing.body.message).toBe('Authorization header is missing or invalid');

		const allowed = await request(server.app).get('/api/custom/apikey').set('Authorization', 'Bearer key-123');
		expect(allowed.status).toBe(200);
		expect(allowed.body).toEqual({ uid: 'api-user', token: 'key-123' });
	});
});
