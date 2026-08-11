import { expect, it } from 'vitest';

import { MemoryOAuthStore } from '../../../src/oauth/memory.js';

import { runOAuthStoreSuite } from './oauth-store-suite.js';

runOAuthStoreSuite('MemoryOAuthStore', async () => {
	const store = new MemoryOAuthStore();
	return { store };
});

it('MemoryOAuthStore enforces maxAuthCodes by evicting oldest codes', async () => {
	const store = new MemoryOAuthStore({ maxAuthCodes: 1 });
	await store.createClient({
		clientId: 'cap-client',
		clientSecret: 'secret',
		redirectUris: ['https://example.com/callback']
	});
	await store.createAuthCode({
		code: 'first',
		clientId: 'cap-client',
		userId: '1',
		redirectUri: 'https://example.com/callback',
		scope: ['read'],
		expiresAt: new Date(Date.now() + 10_000)
	});
	await store.createAuthCode({
		code: 'second',
		clientId: 'cap-client',
		userId: '1',
		redirectUri: 'https://example.com/callback',
		scope: ['read'],
		expiresAt: new Date(Date.now() + 10_000)
	});

	expect(await store.consumeAuthCode('first')).toBeNull();
	expect(await store.consumeAuthCode('second')).not.toBeNull();
});
