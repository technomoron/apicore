import { expect, it } from 'vitest';

import { MemoryPasskeyStore } from '../../../src/passkey/memory.js';

import { runPasskeyStoreSuite } from './passkey-store-suite.js';

const resolveUser = async (params: { userId?: number | string; login?: string }) => {
	if (!params.userId && !params.login) {
		return null;
	}
	const id = params.userId ?? 1;
	const login = params.login ?? 'alice';
	return { id, login, displayName: login };
};

runPasskeyStoreSuite('MemoryPasskeyStore', async () => {
	const store = new MemoryPasskeyStore({ resolveUser });
	return { store };
});

it('MemoryPasskeyStore enforces maxChallenges by evicting oldest challenge', async () => {
	const store = new MemoryPasskeyStore({ resolveUser, maxChallenges: 1 });
	await store.saveChallenge({
		challenge: 'challenge-old',
		action: 'authenticate',
		userId: '1',
		login: 'alice',
		expiresAt: new Date(Date.now() + 10_000)
	});
	await store.saveChallenge({
		challenge: 'challenge-new',
		action: 'authenticate',
		userId: '1',
		login: 'alice',
		expiresAt: new Date(Date.now() + 10_000)
	});

	expect(await store.consumeChallenge('challenge-old')).toBeNull();
	expect(await store.consumeChallenge('challenge-new')).not.toBeNull();
});
