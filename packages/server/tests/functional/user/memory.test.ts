import { expect, it } from 'vitest';

import { MemoryUserStore } from '../../../src/user/memory.js';

import { runUserStoreSuite } from './user-store-suite.js';

runUserStoreSuite('MemoryUserStore', async () => {
	const store = new MemoryUserStore();
	return { store };
});

it('MemoryUserStore enforces maxUsers', async () => {
	const store = new MemoryUserStore({ maxUsers: 1 });
	await store.createUser({
		login: 'one',
		email: 'one@example.com',
		password: 'pw1'
	});
	await expect(
		store.createUser({
			login: 'two',
			email: 'two@example.com',
			password: 'pw2'
		})
	).rejects.toThrow(/maxUsers/i);
});
