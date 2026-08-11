import { describe, it, expect, vi } from 'vitest';

import ApiServer, { ApiError, type ApiRequest } from '../../src/apicore-server';
import { buildAuthCookieOptions } from '../../src/auth-cookie-options';
import { TestServer } from '../helpers/test-server';

class DefaultAuthorizationServer extends ApiServer {
	public checkAuthorization(apiReq: ApiRequest, requiredClass: 'any' | 'admin'): Promise<void> {
		return super.authorize(apiReq, requiredClass);
	}
}

describe('ApiServer config & helpers', () => {
	it('merges default configuration values', () => {
		const server = new TestServer({ apiPort: 4100, apiHost: '0.0.0.0' });
		expect(server.config.apiPort).toBe(4100);
		expect(server.config.apiHost).toBe('0.0.0.0');
		expect(server.config.apiBasePath).toBe('/api');
		expect(server.config.accessCookie).toBe('dat');
		expect(server.config.cookieDomain).toBe('');
		expect(server.config.cookiePath).toBe('/');
		expect(server.config.cookieSameSite).toBe('lax');
		expect(server.config.cookieSecure).toBe('auto');
		expect(server.config.cookieHttpOnly).toBe(true);
		expect(server.config.apiKeyPrefix).toBe('');
		expect(server.config.apiKeyEnabled).toBe(false);
		expect(server.config.signer).toBeUndefined();
		expect(server.config.tokenParam).toBe('');
		expect(server.config.tokenParamLocation).toBe('body');
		expect(server.config.trustProxy).toBe(false);
		expect(server.config.uploadPath).toBe('./uploads');
		expect(server.config.uploadCleanup).toBe('lazy');
		expect(server.config.uploadCleanupIntervalSeconds).toBe(15 * 60);
		expect(server.config.uploadOrphanExpirySeconds).toBe(24 * 60 * 60);
		expect(server.config.multipartEnabled).toBe(false);
	});

	it('accepts each upload cleanup mode and validates cleanup timing values', () => {
		const interval = new TestServer({
			uploadCleanup: 'interval',
			uploadCleanupIntervalSeconds: 30,
			uploadOrphanExpirySeconds: 120
		});
		expect(interval.config.uploadCleanup).toBe('interval');
		expect(interval.config.uploadCleanupIntervalSeconds).toBe(30);
		expect(interval.config.uploadOrphanExpirySeconds).toBe(120);

		const off = new TestServer({ uploadCleanup: 'off' });
		expect(off.config.uploadCleanup).toBe('off');

		const invalid = new TestServer({
			uploadCleanup: 'invalid' as never,
			uploadCleanupIntervalSeconds: 0,
			uploadOrphanExpirySeconds: Number.NaN
		});
		expect(invalid.config.uploadCleanup).toBe('lazy');
		expect(invalid.config.uploadCleanupIntervalSeconds).toBe(15 * 60);
		expect(invalid.config.uploadOrphanExpirySeconds).toBe(24 * 60 * 60);
	});

	it('guessExceptionText handles primitives and defaults', () => {
		const server = new TestServer();
		expect(server.guessExceptionText('simple message')).toBe('simple message');
		expect(server.guessExceptionText(new Error('fail'))).toBe('fail');
		expect(
			server.guessExceptionText({
				parent: { message: 'parent message' }
			})
		).toBe('parent message');
		expect(server.guessExceptionText(null)).toBe('Unknown Error');
	});

	it('throws ApiError when authorization class rejected', async () => {
		const server = new TestServer();
		await expect(
			server.authorize(
				{
					server,
					req: {} as never,
					res: {} as never,
					tokenData: { uid: 'user-1' }
				},
				'admin'
			)
		).rejects.toBeInstanceOf(ApiError);
	});

	it('enforces the admin class in the base server implementation', async () => {
		const server = new DefaultAuthorizationServer();
		const request = {
			server,
			tokenData: { uid: 'user-1', role: 'any' }
		} as ApiRequest;

		await expect(server.checkAuthorization(request, 'admin')).rejects.toMatchObject({
			code: 403
		});
		request.tokenData = { uid: 'admin-1', role: 'admin' };
		await expect(server.checkAuthorization(request, 'admin')).resolves.toBeUndefined();
	});

	it('ignores forwarded protocol headers unless the proxy is trusted', () => {
		const options = buildAuthCookieOptions(
			{ cookieSecure: 'auto', trustProxy: false },
			{
				headers: { 'x-forwarded-proto': 'https' },
				protocol: 'http'
			}
		);

		expect(options.secure).toBe(false);
	});

	it('uses the trusted rightmost forwarded protocol for numeric proxy depth', () => {
		const options = buildAuthCookieOptions(
			{ cookieSecure: 'auto', trustProxy: 1 },
			{
				headers: { 'x-forwarded-proto': 'http,https' },
				protocol: 'http'
			}
		);

		expect(options.secure).toBe(true);
	});

	it('only warns about insecure auth cookies when authentication is configured', () => {
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
		try {
			new ApiServer();
			expect(warnSpy.mock.calls.flat().join(' ')).not.toContain('Auth cookies will omit');

			new ApiServer({ accessSecret: 'access', refreshSecret: 'refresh' });
			expect(warnSpy.mock.calls.flat().join(' ')).toContain('Auth cookies will omit');
		} finally {
			warnSpy.mockRestore();
		}
	});

	it('warns once when assigning deprecated currReq in dev mode', () => {
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
		try {
			const server = new TestServer({ devMode: true });
			server.currReq = null;
			server.currReq = null;
			expect(warnSpy).toHaveBeenCalledTimes(1);
			expect(String(warnSpy.mock.calls[0]?.[0] ?? '')).toContain('ApiServer.currReq is deprecated');
		} finally {
			warnSpy.mockRestore();
		}
	});
});
