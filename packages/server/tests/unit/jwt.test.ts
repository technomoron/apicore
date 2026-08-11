import { describe, it, expect } from 'vitest';

import { createServer, signToken } from '../helpers/test-server';

describe('JWT helpers', () => {
	it('signs, verifies, and decodes JWT tokens', () => {
		const server = createServer();
		const token = signToken(server, { uid: 'user-1' });
		const verify = server.jwtVerify(token, server.config.accessSecret);
		expect(verify.success).toBe(true);
		expect(verify.data?.uid).toBe('user-1');

		const decoded = server.jwtDecode(token);
		expect(decoded.success).toBe(true);
		expect(decoded.data?.uid).toBe('user-1');
	});

	it('flags expired JWTs', () => {
		const server = createServer();
		const token = signToken(server, { uid: 'user-1' }, -10);
		const verify = server.jwtVerify(token, server.config.accessSecret);
		expect(verify.success).toBe(false);
		expect(verify.expired).toBe(true);
	});

	it('decode reports malformed JWTs', () => {
		const server = createServer();
		const decoded = server.jwtDecode('not-a-token');
		expect(decoded.success).toBe(false);
		expect(decoded.error).toBeTruthy();
	});

	it('rejects JWT signed with a different secret', () => {
		const server = createServer();
		const token = signToken(server, { uid: 'user-1' });
		const verify = server.jwtVerify(token, 'wrong-secret');
		expect(verify.success).toBe(false);
		expect(verify.expired).toBe(false);
	});

	it('rejects JWT verified with empty secret', () => {
		const server = createServer();
		const token = signToken(server, { uid: 'user-1' });
		const verify = server.jwtVerify(token, '');
		expect(verify.success).toBe(false);
	});

	it('allows supported HMAC algorithms and respects an explicit algorithm restriction', () => {
		const server = createServer();
		const signed = server.jwtSign({ uid: 'user-1' }, server.config.accessSecret, 60, {
			algorithm: 'HS512'
		});
		if (!signed.success || !signed.token) {
			throw new Error(signed.error ?? 'Failed to sign token');
		}

		expect(server.jwtVerify(signed.token, server.config.accessSecret).success).toBe(true);
		expect(
			server.jwtVerify(signed.token, server.config.accessSecret, {
				algorithms: ['HS256']
			}).success
		).toBe(false);
	});
});
