import { beforeAll, afterAll, describe, it, expect } from 'vitest';

import { createIntegrationHarness } from './helpers.js';

import type { IntegrationHarness } from './helpers.js';
import type { ApiLoginRes, ApiRefreshRes } from '../../src/index.js';

let harness: IntegrationHarness;

beforeAll(async () => {
	harness = await createIntegrationHarness();
});

afterAll(async () => {
	await harness.stop();
});

describe('login flow', () => {
	it('logs in with correct credentials and returns tokens', async () => {
		const res = await harness.client.login<ApiLoginRes>('alice', 'pass123');
		expect(res.success).toBe(true);
		expect(res.data?.accessToken).toBeDefined();
		expect(res.data?.refreshToken).toBeDefined();
		expect(res.data?.user).toBeDefined();
	});

	it('rejects wrong credentials with 400', async () => {
		// The auth module returns 400 (not 401) for invalid credentials
		const res = await harness.client.login('alice', 'wrong-password');
		expect(res.success).toBe(false);
		expect(res.code).toBe(400);
	});

	it('rejects unknown user with 400', async () => {
		const res = await harness.client.login('nobody', 'pass123');
		expect(res.success).toBe(false);
		expect(res.code).toBe(400);
	});
});

describe('me flow', () => {
	it('resolves identity after login using the stored access token', async () => {
		const { client, stop } = await createIntegrationHarness();
		try {
			const loginRes = await client.login<ApiLoginRes>('alice', 'pass123');
			expect(loginRes.success).toBe(true);

			const meRes = await client.me();
			expect(meRes.success).toBe(true);
			expect(meRes.data?.user).toBeDefined();
			expect(meRes.data?.ruser).toBeUndefined();
		} finally {
			await stop();
		}
	});

	it('does not expose the legacy whoami endpoint', async () => {
		const { client, stop } = await createIntegrationHarness();
		try {
			const res = await client.post('/api/auth/v1/whoami', {});
			expect(res.success).toBe(false);
			expect(res.code).toBe(404);
		} finally {
			await stop();
		}
	});
});

describe('logout flow', () => {
	it('can logout by passing the refresh token', async () => {
		const { client, stop } = await createIntegrationHarness();
		try {
			const loginRes = await client.login<ApiLoginRes>('alice', 'pass123');
			expect(loginRes.success).toBe(true);
			const refreshToken = client.get_refresh_token();
			expect(refreshToken).toBeTruthy();

			// Pass the refresh token explicitly to logout
			const logoutRes = await client.logout(refreshToken ?? '');
			expect(logoutRes.success).toBe(true);

			// After logout, local tokens are cleared, so identity lookup should fail.
			const afterRes = await client.me();
			expect(afterRes.success).toBe(false);
			expect(afterRes.code).toBe(401);
		} finally {
			await stop();
		}
	});
});

describe('token refresh endpoint', () => {
	it('issues new tokens when a valid refresh token is posted', async () => {
		const { client, stop } = await createIntegrationHarness();
		try {
			const loginRes = await client.login<ApiLoginRes>('alice', 'pass123');
			expect(loginRes.success).toBe(true);
			const refreshToken = client.get_refresh_token();
			expect(refreshToken).toBeTruthy();

			const refreshRes = await client.post<ApiRefreshRes>('/api/auth/v1/refresh', { refreshToken });
			expect(refreshRes.success).toBe(true);
			expect(refreshRes.data?.accessToken).toBeDefined();
			expect(refreshRes.data?.refreshToken).toBeDefined();
			expect('user' in (refreshRes.data ?? {})).toBe(false);
			expect('ruser' in (refreshRes.data ?? {})).toBe(false);
			// New tokens should differ from the originals
			expect(refreshRes.data?.accessToken).not.toBe(loginRes.data?.accessToken);
		} finally {
			await stop();
		}
	});

	it('rejects an invalid refresh token with 401', async () => {
		const { client, stop } = await createIntegrationHarness();
		try {
			const res = await client.post('/api/auth/v1/refresh', {
				refreshToken: 'invalid-token'
			});
			expect(res.success).toBe(false);
			expect(res.code).toBe(401);
		} finally {
			await stop();
		}
	});
});
