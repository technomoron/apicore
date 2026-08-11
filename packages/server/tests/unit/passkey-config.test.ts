import { describe, expect, it } from 'vitest';

import { normalizePasskeyConfig } from '../../src/passkey/config.js';

describe('normalizePasskeyConfig', () => {
	it('applies defaults when no values are provided', () => {
		const config = normalizePasskeyConfig();
		expect(config.rpId).toBe('localhost');
		expect(config.rpName).toBe('API Server');
		expect(config.origins).toEqual(['http://localhost:5173']);
		expect(config.timeoutMs).toBe(5 * 60 * 1000);
		expect(config.userVerification).toBe('preferred');
		expect(config.debug).toBe(false);
	});

	it('normalizes provided values and filters invalid origins', () => {
		const config = normalizePasskeyConfig({
			rpId: '  my-rp  ',
			rpName: '  My RP  ',
			origins: [' https://app.example.com ', '', 'https://api.example.com'],
			timeoutMs: 1234,
			userVerification: 'required',
			debug: true
		});
		expect(config.rpId).toBe('my-rp');
		expect(config.rpName).toBe('My RP');
		expect(config.origins).toEqual(['https://app.example.com', 'https://api.example.com']);
		expect(config.timeoutMs).toBe(1234);
		expect(config.userVerification).toBe('required');
		expect(config.debug).toBe(true);
	});
});
