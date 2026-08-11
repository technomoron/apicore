import request from 'supertest';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { createServer } from '../helpers/test-server';

describe('CORS & debugging', () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});

	afterEach(() => {
		vi.resetAllMocks();
	});

	it('applies CORS allow list', async () => {
		const server = createServer({ origins: ['http://allowed.test'] });
		const ok = await request(server.app).get('/api/example/public').set('Origin', 'http://allowed.test');
		expect(ok.headers['access-control-allow-origin']).toBe('http://allowed.test');

		const blocked = await request(server.app).get('/api/example/public').set('Origin', 'http://blocked.test');
		expect(blocked.status).toBe(403);
		expect(blocked.body).toEqual({
			success: false,
			code: 403,
			message: 'Origin not allowed by CORS',
			data: null,
			errors: {}
		});
	});

	it('defaults to same-origin only when no origins are configured', async () => {
		const server = createServer({ origins: [] });

		// No Access-Control-Allow-Origin is emitted, so the browser refuses to
		// expose the response to a cross-origin caller.
		const cross = await request(server.app).get('/api/example/public').set('Origin', 'http://evil.test');
		expect(cross.headers['access-control-allow-origin']).toBeUndefined();
		expect(cross.headers['access-control-allow-credentials']).toBeUndefined();

		// Same-origin requests must keep working: browsers send Origin on
		// same-origin POST/PUT/DELETE too, so this must not be rejected.
		const samePost = await request(server.app)
			.patch('/api/example/patchable')
			.set('Origin', 'http://allowed.test')
			.send({ value: 1 });
		expect(samePost.status).toBeLessThan(400);

		// Non-browser clients omit Origin entirely and are unaffected.
		const noOrigin = await request(server.app).get('/api/example/public');
		expect(noOrigin.status).toBe(200);
	});

	it('reflects any origin only when corsAllowAll is explicitly enabled', async () => {
		const server = createServer({ origins: [], corsAllowAll: true });
		const res = await request(server.app).get('/api/example/public').set('Origin', 'http://evil.test');
		expect(res.headers['access-control-allow-origin']).toBe('http://evil.test');
		expect(res.headers['access-control-allow-credentials']).toBe('true');
	});

	it('treats devMode as an implicit corsAllowAll', async () => {
		const server = createServer({ origins: [], devMode: true });
		expect(server.config.corsAllowAll).toBe(true);
		const res = await request(server.app).get('/api/example/public').set('Origin', 'http://localhost:5173');
		expect(res.headers['access-control-allow-origin']).toBe('http://localhost:5173');
	});

	it('lets an explicit origins allowlist override corsAllowAll', async () => {
		const server = createServer({
			origins: ['http://allowed.test'],
			corsAllowAll: true
		});
		const blocked = await request(server.app).get('/api/example/public').set('Origin', 'http://evil.test');
		expect(blocked.status).toBe(403);
		expect(blocked.headers['access-control-allow-origin']).toBeUndefined();
	});

	it('warns when corsAllowAll is enabled outside devMode', () => {
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
		createServer({ origins: [], corsAllowAll: true });
		expect(warnSpy.mock.calls.flat().join(' ')).toContain('corsAllowAll is enabled');
		warnSpy.mockRestore();
	});

	it('stays quiet about CORS in devMode', () => {
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
		createServer({ origins: [], devMode: true });
		expect(warnSpy.mock.calls.flat().join(' ')).not.toContain('corsAllowAll is enabled');
		warnSpy.mockRestore();
	});

	it('redacts token-like fields from debug response dumps', async () => {
		const server = createServer({ debug: true });
		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		await request(server.app).post('/api/example/echo-secrets').send({});

		const payloadCall = logSpy.mock.calls.find(([label]) => label === 'Payload:');
		const payload = payloadCall?.[1] as { data?: Record<string, unknown> };
		expect(payload.data?.accessToken).toBe('[REDACTED]');
		expect(payload.data?.refreshToken).toBe('[REDACTED]');
		expect(payload.data?.apiKey).toBe('[REDACTED]');
		// Non-sensitive fields must survive so the dump stays useful.
		expect(payload.data?.userId).toBe('user-1');
		logSpy.mockRestore();
	});

	it('dumps request metadata when debug enabled', async () => {
		const server = createServer({ debug: true });
		server.config.debug = true;
		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		await request(server.app).get('/api/example/public').set('Origin', 'http://allowed.test');

		expect(logSpy).toHaveBeenCalledWith('--- Incoming Request! ---');
		logSpy.mockRestore();
	});

	it('redacts token-like fields from debug request dumps', async () => {
		const server = createServer({ debug: true });
		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

		await request(server.app)
			.patch('/api/example/patchable')
			.send({
				refreshToken: 'refresh-secret',
				client_secret: 'oauth-secret',
				nested: { token: 'nested-secret' }
			});

		const bodyCall = logSpy.mock.calls.find(([label]) => label === 'Body Params:');
		expect(bodyCall?.[1]).toEqual({
			refreshToken: '[REDACTED]',
			client_secret: '[REDACTED]',
			nested: { token: '[REDACTED]' }
		});
		logSpy.mockRestore();
	});
});
