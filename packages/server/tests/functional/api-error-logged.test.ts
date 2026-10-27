import { appendFile } from 'node:fs/promises';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiError, ApiErrorLogged, ApiModule, type ApiRoute } from '../../src/apicore-server';
import { TestServer } from '../helpers/test-server';

vi.mock('node:fs/promises', async (importOriginal) => ({
	...(await importOriginal<typeof import('node:fs/promises')>()),
	appendFile: vi.fn().mockResolvedValue(undefined)
}));

// Provide both logged and unexpected failures through API routes.
class ErrorModule extends ApiModule {
	// Register error cases without authentication requirements.
	public override defineRoutes(): ApiRoute[] {
		return [
			{
				method: 'get',
				path: '/logged',
				auth: { type: 'none', req: 'any' },
				handler: async () => {
					throw new ApiErrorLogged({
						code: 502,
						message: 'Try again',
						data: { retry: true },
						errors: { profile: 'Unavailable' },
						cause: new Error('Database offline\npassword=hunter2')
					});
				}
			},
			{
				method: 'get',
				path: '/unexpected',
				auth: { type: 'none', req: 'any' },
				handler: async () => {
					throw Object.assign(new Error('Database offline'), { statusCode: 503 });
				}
			}
		];
	}
}

// Check the log destination, correlation, and physical line count.
function assertLog(errorId: string): string {
	const call = vi.mocked(appendFile).mock.calls.at(-1)!;
	expect(call[0]).toBe('/var/log/apicore-profile.log');
	const line = String(call[1]);
	expect(line.trim().split('\n')).toHaveLength(1);
	expect(JSON.parse(line)).toMatchObject({ appName: 'profile', pid: process.pid, errorId });
	return line;
}

describe('ApiErrorLogged', () => {
	afterEach(() => vi.clearAllMocks());

	it('uses the configured log file while retaining app identity', async () => {
		const server = new TestServer({ appName: 'profile', logFile: '/tmp/profile-errors.log' });
		server.api(new ErrorModule({ namespace: '/errors' }));
		const response = await server.fastify.inject({ url: '/api/errors/logged' });
		expect(response.statusCode).toBe(502);
		const call = vi.mocked(appendFile).mock.calls.at(-1)!;
		expect(call[0]).toBe('/tmp/profile-errors.log');
		expect(JSON.parse(String(call[1]))).toMatchObject({ appName: 'profile', errorId: response.json().errorId });
		await server.fastify.close();
	});

	it('inherits ApiError and keeps cause non-enumerable', () => {
		const cause = new Error('private');
		const error = new ApiErrorLogged({ message: 'public', cause });
		expect(error).toBeInstanceOf(ApiError);
		expect(error.cause).toBe(cause);
		expect(JSON.stringify(error)).not.toContain('private');
	});

	it.each(['api', 'fastify', 'express'])('preserves public fields and masks cause through %s', async (kind) => {
		const server = new TestServer({ appName: 'profile', debug: true });
		server.api(new ErrorModule({ namespace: '/errors' }));
		server.fastify.get('/native', async () => {
			throw new ApiErrorLogged({
				code: 502,
				message: 'Try again',
				data: { retry: true },
				errors: { profile: 'Unavailable' },
				cause: new Error('Database offline\npassword=hunter2')
			});
		});
		let body: Record<string, unknown>;
		if (kind === 'express') {
			const res = { headersSent: false, status: vi.fn().mockReturnThis(), json: vi.fn() };
			server.expressErrorHandler()(
				new ApiErrorLogged({
					code: 502,
					message: 'Try again',
					data: { retry: true },
					errors: { profile: 'Unavailable' },
					cause: new Error('Database offline\npassword=hunter2')
				}),
				{} as never,
				res as never,
				vi.fn()
			);
			expect(res.status).toHaveBeenCalledWith(502);
			body = res.json.mock.calls[0][0];
		} else {
			const response = await server.fastify.inject({ url: kind === 'api' ? '/api/errors/logged' : '/native' });
			expect(response.statusCode).toBe(502);
			body = response.json();
		}
		expect(body).toEqual({
			success: false,
			code: 502,
			message: 'Try again',
			data: { retry: true },
			errors: { profile: 'Unavailable' },
			errorId: expect.stringMatching(/^[A-Za-z0-9_-]{12}$/)
		});
		expect(JSON.stringify(body)).not.toContain('Database');
		const line = assertLog(String(body.errorId));
		expect(line).toContain('Database offline');
		expect(line).not.toContain('hunter2');
		await server.fastify.close();
	});

	it.each(['api', 'fastify', 'express'])('masks unexpected errors through %s even in debug mode', async (kind) => {
		const server = new TestServer({ appName: 'profile', debug: true });
		server.api(new ErrorModule({ namespace: '/errors' }));
		server.fastify.get('/native', async () => {
			throw new Error('private failure');
		});
		let body: Record<string, unknown>;
		if (kind === 'express') {
			const res = { headersSent: false, status: vi.fn().mockReturnThis(), json: vi.fn() };
			server.expressErrorHandler()(
				Object.assign(new Error('private failure'), { statusCode: 503 }),
				{} as never,
				res as never,
				vi.fn()
			);
			expect(res.status).toHaveBeenCalledWith(500);
			body = res.json.mock.calls[0][0];
		} else {
			const response = await server.fastify.inject({
				url: kind === 'api' ? '/api/errors/unexpected' : '/native'
			});
			expect(response.statusCode).toBe(500);
			body = response.json();
		}
		expect(body).toEqual({
			success: false,
			code: 500,
			message: 'Internal server error',
			data: null,
			errors: {},
			errorId: expect.stringMatching(/^[A-Za-z0-9_-]{12}$/)
		});
		assertLog(String(body.errorId));
		await server.fastify.close();
	});
});
