import { expect, it } from 'vitest';

import type { AuthIdentifier } from '../../../src/auth-api/types.js';
import type { PasskeyStore } from '../../../src/passkey/base.js';
import type { PasskeyChallengeRecord, StoredPasskeyCredential } from '../../../src/passkey/types.js';

interface SuiteContext {
	store: PasskeyStore;
	cleanup?: () => Promise<void>;
}

type StoreFactory = () => Promise<SuiteContext>;

function sampleCredential(userId: AuthIdentifier): StoredPasskeyCredential {
	return {
		userId,
		credentialId: Buffer.from('cred-1'),
		publicKey: Buffer.from('pubkey-1'),
		counter: 0,
		backedUp: false,
		deviceType: 'multiDevice',
		label: 'Primary Key',
		createdDomain: 'example.com',
		createdUserAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0_0)',
		createdBrowser: 'Chrome 123.0',
		createdOs: 'macOS 14.0',
		createdDevice: 'Mac',
		createdIp: '203.0.113.10'
	};
}

function sampleChallenge(userId: AuthIdentifier): PasskeyChallengeRecord {
	return {
		challenge: 'challenge-1',
		action: 'authenticate',
		userId,
		login: 'alice',
		expiresAt: new Date(Date.now() + 1000)
	};
}

export function runPasskeyStoreSuite(label: string, factory: StoreFactory): void {
	it(`${label} - credentials and challenges`, async () => {
		const { store, cleanup } = await factory();
		try {
			const userId: AuthIdentifier = 1;
			const credential = sampleCredential(userId);
			await store.saveCredential(credential);

			const listed = await store.listUserCredentials(userId);
			expect(listed.length).toBe(1);
			expect(listed[0].counter).toBe(0);
			expect(listed[0].label).toBe('Primary Key');
			expect(listed[0].createdDomain).toBe('example.com');
			expect(listed[0].createdBrowser).toBe('Chrome 123.0');
			expect(listed[0].createdOs).toBe('macOS 14.0');
			expect(listed[0].createdDevice).toBe('Mac');
			expect(listed[0].createdIp).toBe('203.0.113.10');

			const fetched = await store.findCredentialById(Buffer.from('cred-1'));
			expect(fetched?.publicKey.toString()).toBe('pubkey-1');
			expect(fetched?.createdUserAgent).toBe('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0_0)');
			if (!fetched) {
				throw new Error('Expected fetched credential');
			}
			fetched.publicKey[0] = 0x00;
			const fetchedAgain = await store.findCredentialById(Buffer.from('cred-1'));
			expect(fetchedAgain?.publicKey.toString()).toBe('pubkey-1');

			await store.updateCredentialCounter(Buffer.from('cred-1'), 5);
			const updated = await store.findCredentialById(Buffer.from('cred-1'));
			expect(updated?.counter).toBe(5);
			expect(updated?.label).toBe('Primary Key');

			const challenge = sampleChallenge(userId);
			await store.saveChallenge(challenge);
			const consumed = await store.consumeChallenge(challenge.challenge);
			expect(consumed?.login).toBe('alice');
			const missing = await store.consumeChallenge(challenge.challenge);
			expect(missing).toBeNull();

			await store.saveChallenge({
				...challenge,
				challenge: 'expired',
				expiresAt: new Date(Date.now() - 1000)
			});
			await store.cleanupChallenges(new Date());
			expect(await store.consumeChallenge('expired')).toBeNull();
		} finally {
			await cleanup?.();
		}
	});

	it(`${label} - deleteCredential removes and returns correct result`, async () => {
		const { store, cleanup } = await factory();
		try {
			const userId: AuthIdentifier = 2;
			const credential = sampleCredential(userId);
			await store.saveCredential(credential);

			const listed = await store.listUserCredentials(userId);
			expect(listed.length).toBe(1);

			const deleted = await store.deleteCredential(Buffer.from('cred-1'));
			expect(deleted).toBe(true);

			const afterDelete = await store.listUserCredentials(userId);
			expect(afterDelete.length).toBe(0);

			// Double-delete should return false
			const doubleDelete = await store.deleteCredential(Buffer.from('cred-1'));
			expect(doubleDelete).toBe(false);
		} finally {
			await cleanup?.();
		}
	});
}
