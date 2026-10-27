import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createServer } from '../helpers/test-server';

describe('Error handling', () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('formats ApiError responses consistently', async () => {
		const server = createServer();
		const response = await request(server.app).get('/api/example/boom');
		expect(response.status).toBe(418);
		expect(response.body).toEqual({
			success: false,
			code: 418,
			message: 'Teapot',
			data: { reason: 'test' },
			errors: { field: 'bad' }
		});
	});

	it('guards against unexpected errors', async () => {
		const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
		const server = createServer();
		const response = await request(server.app).get('/api/example/crash');
		expect(response.status).toBe(500);
		expect(response.body.code).toBe(500);
		expect(response.body.message).toBe('Internal server error');
		expect(response.body.errors).toEqual({});
		expect(errorSpy).toHaveBeenCalled();
	});

	it('masks unexpected errors in debug mode', async () => {
		const server = createServer({ debug: true });
		const response = await request(server.app).get('/api/example/crash');
		expect(response.status).toBe(500);
		expect(response.body.code).toBe(500);
		expect(response.body.message).toBe('Internal server error');
		expect(response.body.errorId).toMatch(/^[A-Za-z0-9_-]{12}$/);
		expect(response.body.errors).toEqual({});
	});

	it('rejects handlers that return non-array results', async () => {
		const server = createServer();
		const response = await request(server.app).get('/api/example/invalid-result');
		expect(response.status).toBe(500);
		expect(response.body).toEqual({
			success: false,
			code: 500,
			message: 'Handler result must be an array: [status, data?, message?]',
			data: null,
			errors: {}
		});
	});

	it('rejects handlers whose first element is not numeric', async () => {
		const server = createServer();
		const response = await request(server.app).get('/api/example/bad-status');
		expect(response.status).toBe(500);
		expect(response.body).toEqual({
			success: false,
			code: 500,
			message: 'Handler result must start with a numeric status code',
			data: null,
			errors: {}
		});
	});

	it('returns JSON 404 responses for unknown namespaces', async () => {
		const server = createServer();
		const response = await request(server.app).get('/api/missing/path');
		expect(response.status).toBe(404);
		expect(response.body).toEqual({
			success: false,
			code: 404,
			message: 'No such endpoint: GET /api/missing/path',
			data: null,
			errors: {}
		});
	});

	it('marks handler-level 4xx responses as unsuccessful', async () => {
		const server = createServer();
		const response = await request(server.app).get('/api/example/handler-404');
		expect(response.status).toBe(404);
		expect(response.body).toEqual({
			success: false,
			code: 404,
			message: 'Handler-level missing',
			data: null,
			errors: {}
		});
	});

	it('includes method and original URL in the 404 message for known namespaces', async () => {
		const server = createServer();
		const response = await request(server.app).post('/api/example/absent?foo=bar');
		expect(response.status).toBe(404);
		expect(response.body).toEqual({
			success: false,
			code: 404,
			message: 'No such endpoint: POST /api/example/absent?foo=bar',
			data: null,
			errors: {}
		});
	});

	it('returns API envelope for malformed JSON bodies', async () => {
		const server = createServer();
		const response = await request(server.app)
			.post('/api/example/absent')
			.set('Content-Type', 'application/json')
			.send('{"broken":');
		expect(response.status).toBe(400);
		expect(response.body).toEqual({
			success: false,
			code: 400,
			message: 'Invalid request payload',
			data: null,
			errors: {}
		});
	});
});
