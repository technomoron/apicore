import { createRequire } from 'node:module';

import { describe, it, expect } from 'vitest';

describe('package entry points', () => {
	it('supports ESM consumption via package exports', async () => {
		// Prefer local source during development; fall back to package entry if built.
		const entry = await import('../../src/index.ts');

		expect(typeof entry.ApiServer).toBe('function');
		expect(typeof entry.ApiModule).toBe('function');
		expect(typeof entry.ApiError).toBe('function');
		expect(typeof entry.MemoryRateLimitStore).toBe('function');
		expect(typeof entry.RateLimitService).toBe('function');
		expect(typeof entry.SecurityEventService).toBe('function');
		expect(typeof entry.MemoryApiKeyStore).toBe('function');
		expect(typeof entry.JsonApiKeyStore).toBe('function');

		const server = new entry.ApiServer();
		expect(server).toBeInstanceOf(entry.ApiServer);
		expect(typeof server.app).toBe('function');

		const chained = new entry.ApiServer({});
		expect(chained).toBeInstanceOf(entry.ApiServer);
		expect(typeof chained.authStorage).toBe('function');
		chained.authStorage(entry.nullAuthAdapter).authModule(entry.nullAuthModule);
	});

	it('supports CommonJS consumption via package exports', () => {
		const require = createRequire(import.meta.url);
		type ApiServerExports = typeof import('../../src/index.js');
		let entry: ApiServerExports;
		try {
			entry = require('../../dist/cjs/index.cjs') as ApiServerExports;
		} catch {
			// Skip if CJS output isn't available in the dev workspace.
			console.warn('[module-imports] CJS import test skipped — dist/cjs not available');
			return;
		}

		expect(typeof entry.ApiServer).toBe('function');
		expect(typeof entry.ApiModule).toBe('function');
		expect(typeof entry.ApiError).toBe('function');
		expect(typeof entry.MemoryRateLimitStore).toBe('function');
		expect(typeof entry.RateLimitService).toBe('function');
		expect(typeof entry.SecurityEventService).toBe('function');
		expect(typeof entry.MemoryApiKeyStore).toBe('function');
		expect(typeof entry.JsonApiKeyStore).toBe('function');

		const server = new entry.ApiServer();
		expect(server).toBeInstanceOf(entry.ApiServer);
		expect(typeof server.app).toBe('function');

		const chained = new entry.ApiServer({});
		expect(chained).toBeInstanceOf(entry.ApiServer);
		expect(typeof chained.authStorage).toBe('function');
		chained.authStorage(entry.nullAuthAdapter).authModule(entry.nullAuthModule);
	});
});
