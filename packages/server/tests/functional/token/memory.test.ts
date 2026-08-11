import { expect, it } from 'vitest';

import { MemoryTokenStore } from '../../../src/token/memory.js';

import { runTokenStoreSuite } from './token-store-suite.js';

runTokenStoreSuite('MemoryTokenStore', () => ({
	store: new MemoryTokenStore()
}));

it('MemoryTokenStore enforces maxTokens by evicting oldest tokens', async () => {
	const store = new MemoryTokenStore({ maxTokens: 2 });
	await store.save({
		userId: '1',
		accessToken: 'a1',
		refreshToken: 'r1',
		clientId: 'c1'
	});
	await store.save({
		userId: '1',
		accessToken: 'a2',
		refreshToken: 'r2',
		clientId: 'c2'
	});
	await store.save({
		userId: '1',
		accessToken: 'a3',
		refreshToken: 'r3',
		clientId: 'c3'
	});

	expect(await store.get({ refreshToken: 'r1' }, { includeExpired: true })).toBeNull();
	expect(await store.get({ refreshToken: 'r2' }, { includeExpired: true })).not.toBeNull();
	expect(await store.get({ refreshToken: 'r3' }, { includeExpired: true })).not.toBeNull();
});
