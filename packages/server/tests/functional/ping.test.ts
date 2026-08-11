import request from 'supertest';
import { describe, it, expect } from 'vitest';

import { createServer } from '../helpers/test-server';

describe('Ping endpoint', () => {
	it('returns ApiResponse<ApiPingRes> with stable metadata', async () => {
		const server = createServer();

		const response = await request(server.app).get('/api/v1/ping');

		expect(response.status).toBe(200);
		expect(response.body.success).toBe(true);
		expect(response.body.code).toBe(200);
		expect(response.body.message).toBe('Success');

		const data = response.body.data;
		expect(data.success).toBe(true);
		expect(data.status).toBe('ok');
		expect(typeof data.uptimeSec).toBe('number');
		expect(data.startedAt).toBe(server.startedAt);
		expect(typeof data.timestamp).toBe('string');
		expect(Number.isNaN(new Date(data.timestamp).getTime())).toBe(false);
	});

	it('rejects unexpected query parameters', async () => {
		const server = createServer();

		const response = await request(server.app).get('/api/v1/ping?verbose=true');

		expect(response.status).toBe(400);
		expect(response.body.message).toBe('Validation failed');
		expect(response.body.errors).toHaveProperty('verbose');
	});
});
