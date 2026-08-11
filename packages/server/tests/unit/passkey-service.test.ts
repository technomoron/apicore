import { describe, expect, it, vi } from 'vitest';

import { PasskeyService } from '../../src/passkey/service.js';

import type { AuthIdentifier } from '../../src/auth-api/types.js';
import type {
	PasskeyChallengeRecord,
	PasskeyStorageAdapter,
	PasskeyUserDescriptor,
	StoredPasskeyCredential
} from '../../src/passkey/types.js';

class StubPasskeyAdapter implements PasskeyStorageAdapter {
	public consumedCount = 0;
	private readonly challenge: PasskeyChallengeRecord | null;

	constructor(challenge: PasskeyChallengeRecord | null) {
		this.challenge = challenge;
	}

	public async resolveUser(): Promise<PasskeyUserDescriptor | null> {
		return { id: 1, login: 'user', displayName: 'User' };
	}
	public async listUserCredentials(): Promise<StoredPasskeyCredential[]> {
		return [];
	}
	public async deleteCredential(): Promise<boolean> {
		return false;
	}
	public async findCredentialById(): Promise<StoredPasskeyCredential | null> {
		return null;
	}
	public async saveCredential(): Promise<void> {
		return;
	}
	public async updateCredentialCounter(): Promise<void> {
		return;
	}
	public async saveChallenge(): Promise<void> {
		return;
	}
	public async getChallenge(): Promise<PasskeyChallengeRecord | null> {
		return this.challenge ? { ...this.challenge } : null;
	}
	public async consumeChallenge(): Promise<PasskeyChallengeRecord | null> {
		this.consumedCount += 1;
		return this.challenge ? { ...this.challenge } : null;
	}
	public async cleanupChallenges(): Promise<void> {
		return;
	}
}

describe('PasskeyService', () => {
	it('checks challenge expiry before consume when adapter supports getChallenge', async () => {
		const adapter = new StubPasskeyAdapter({
			challenge: 'expired-challenge',
			action: 'authenticate',
			userId: 1 as AuthIdentifier,
			expiresAt: new Date(Date.now() - 1000)
		});
		const logger = { error: vi.fn(), warn: vi.fn() };
		const service = new PasskeyService(
			{
				rpId: 'localhost',
				rpName: 'Test RP',
				origins: ['http://localhost'],
				timeoutMs: 60_000,
				userVerification: 'preferred'
			},
			adapter,
			logger
		);

		const result = await service.verifyResponse({
			expectedChallenge: 'expired-challenge',
			response: {}
		});

		expect(result.verified).toBe(false);
		expect(adapter.consumedCount).toBe(0);
	});
});
