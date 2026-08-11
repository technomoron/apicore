import { expect, it } from 'vitest';

import type { AuthIdentifier } from '../../../src/auth-api/types.js';
import type { UserStore } from '../../../src/user/base.js';

interface SuiteContext<UserType> {
	store: UserStore<UserType, unknown>;
	cleanup?: () => Promise<void>;
}

type StoreFactory<UserType> = () => Promise<SuiteContext<UserType>>;

export function runUserStoreSuite<UserType>(label: string, factory: StoreFactory<UserType>): void {
	it(`${label} - create and lookup users`, async () => {
		const { store, cleanup } = await factory();
		try {
			const created = await store.createUser({
				login: 'alice',
				email: 'alice@example.com',
				password: 'secret'
			});
			const userId = store.getUserId(created) as AuthIdentifier;
			expect(userId).toBeTruthy();

			const foundById = await store.findById(userId);
			expect(foundById).not.toBeNull();
			expect(store.getUserId(foundById as UserType)).toEqual(userId);

			const foundByLogin = await store.findUser('alice');
			expect(foundByLogin).not.toBeNull();
			expect(store.getUserId(foundByLogin as UserType)).toEqual(userId);

			const foundByEmail = await store.findUser('alice@example.com');
			expect(foundByEmail).not.toBeNull();
			expect(store.getUserId(foundByEmail as UserType)).toEqual(userId);

			const hash = store.getPasswordHash(created as UserType) as string;
			expect(hash).toBeTypeOf('string');
			expect(hash).not.toEqual('secret');
			const verified = await store.verifyPassword('secret', hash);
			expect(verified).toBe(true);
		} finally {
			await cleanup?.();
		}
	});

	it(`${label} - update paths`, async () => {
		const { store, cleanup } = await factory();
		try {
			const created = await store.createUser({
				login: 'bob',
				email: 'bob@example.com',
				password: 'pw1'
			});
			const userId = store.getUserId(created) as AuthIdentifier;

			const updated = await store.updateUser(userId, {
				email: 'bob@new.example.com'
			});
			expect(updated.email).toEqual('bob@new.example.com');

			const newHash = await store
				.createUser({
					login: 'tmp',
					email: 'tmp@example.com',
					password: 'pw2'
				})
				.then((u) => store.getPasswordHash(u as UserType) as string);
			await store.setPasswordHash(userId, newHash);
			const found = await store.findById(userId);
			expect(found).not.toBeNull();
			const ok = await store.verifyPassword('pw2', store.getPasswordHash(found as UserType) as string);
			expect(ok).toBe(true);
		} finally {
			await cleanup?.();
		}
	});

	it(`${label} - createUser rejects duplicate login/email`, async () => {
		const { store, cleanup } = await factory();
		try {
			await store.createUser({
				login: 'dupe',
				email: 'dupe@example.com',
				password: 'pw1'
			});
			await expect(
				store.createUser({
					login: 'dupe',
					email: 'dupe2@example.com',
					password: 'pw2'
				})
			).rejects.toThrow(/already exists/i);
			await expect(
				store.createUser({
					login: 'dupe2',
					email: 'dupe@example.com',
					password: 'pw3'
				})
			).rejects.toThrow(/already exists/i);
		} finally {
			await cleanup?.();
		}
	});
}
