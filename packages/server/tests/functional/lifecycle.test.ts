import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { ExampleModule, TestServer } from '../helpers/test-server';

describe('ApiServer lifecycle helpers', () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});

	afterEach(() => {
		vi.resetAllMocks();
	});

	it('mounts modules and records mount path', () => {
		const server = new TestServer();
		const module = new ExampleModule();
		server.api(module);
		expect(module.mountpath).toBe('/api/example');
	});

	it('allows modules to mount after async setup before finalize', async () => {
		const server = new TestServer();
		const module = new ExampleModule();

		await new Promise<void>((resolve) => setImmediate(resolve));

		expect(() => server.api(module)).not.toThrow();
		expect(module.mountpath).toBe('/api/example');
	});

	it('throws when module checkConfig returns false', () => {
		class BadModule extends ExampleModule {
			public override checkConfig(): boolean {
				return false;
			}
		}

		const server = new TestServer();
		expect(() => server.api(new BadModule())).toThrowError('BadModule.checkConfig() returned false');
	});

	it('throws a helpful error when ApiModule.server is accessed before mount', () => {
		const module = new ExampleModule();
		expect(() => module.server).toThrowError(
			'ApiModule.server is not set. Mount the module with ApiServer.api(...) before using it.'
		);
	});

	it('start wires listeners and logs success', async () => {
		const server = new TestServer();
		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

		vi.spyOn(server.fastify, 'listen').mockResolvedValue('http://localhost:3101');

		server.finalize();
		const result = server.start();
		expect(result).toBe(server);
		expect(warnSpy).not.toHaveBeenCalled();
		await vi.waitFor(() => {
			expect(logSpy).toHaveBeenCalledWith('Server is running on http://localhost:3101');
		});
	});

	it('handles startup errors gracefully', async () => {
		const server = new TestServer();
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
		const startupError = Object.assign(new Error('boom'), {
			code: 'EADDRINUSE'
		});
		const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

		vi.spyOn(server.fastify, 'listen').mockRejectedValue(startupError);

		server.finalize();
		server.start();
		await vi.waitFor(() => {
			expect(errorSpy).toHaveBeenCalled();
		});
		expect(warnSpy).not.toHaveBeenCalled();
	});

	it('delegates startup errors to onStartError when configured', async () => {
		const onStartError = vi.fn();
		const server = new TestServer({ onStartError });
		const startupError = Object.assign(new Error('boom'), {
			code: 'EADDRINUSE'
		});

		vi.spyOn(server.fastify, 'listen').mockRejectedValue(startupError);

		server.finalize();
		expect(() => server.start()).not.toThrow();
		await vi.waitFor(() => {
			expect(onStartError).toHaveBeenCalledTimes(1);
		});
		expect(onStartError.mock.calls[0]?.[0]).toBeInstanceOf(Error);
		expect((onStartError.mock.calls[0]?.[0] as Error).message).toBe('Port 3101 is already in use.');
	});

	it('auto-finalizes on start when finalize is not called', () => {
		const server = new TestServer();
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

		vi.spyOn(server.fastify, 'listen').mockResolvedValue('http://localhost:3101');

		server.start();

		expect(warnSpy).toHaveBeenCalledTimes(1);
		expect(String(warnSpy.mock.calls[0]?.[0] ?? '')).toContain('auto-finalizing');
		expect(() => server.useExpress('/api/custom/ping', (_req, res) => res.status(200).json({ ok: true }))).toThrow(
			'Cannot call ApiServer.useExpress() after finalize()/start()'
		);
	});

	it('supports token persistence helpers', async () => {
		const server = new TestServer();
		const storage = server.storage;
		await storage.storeToken({
			accessToken: 'a',
			refreshToken: 'r',
			userId: 'u'
		});
		expect(server.storedTokens).toHaveLength(1);
		expect(await storage.getToken({ refreshToken: 'r' })).toEqual(
			expect.objectContaining({
				accessToken: 'a',
				refreshToken: 'r',
				userId: 'u'
			})
		);
		expect(await storage.verifyPassword('pw', 'pw')).toBe(true);
		expect(await storage.verifyPassword('pw', 'wrong')).toBe(false);

		await server.updateToken({
			accessToken: 'a-updated',
			refreshToken: 'r'
		});
		expect(await storage.getToken({ refreshToken: 'r' })).toEqual(
			expect.objectContaining({
				accessToken: 'a-updated',
				refreshToken: 'r'
			})
		);
		expect(await storage.deleteToken({ refreshToken: 'r' })).toBe(1);
		expect(await storage.getToken({ refreshToken: 'r' })).toBeNull();

		server.users.set('user-2', {
			id: 'user-2',
			email: 'user2@test.dev',
			role: 'any',
			password: 'secret'
		});
		expect(storage.filterUser(server.users.get('user-2')!)).toEqual({
			id: 'user-2',
			email: 'user2@test.dev',
			role: 'any'
		});
	});
});
