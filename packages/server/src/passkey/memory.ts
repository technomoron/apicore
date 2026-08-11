import { normalizeComparableUserId } from '../auth-api/user-id.js';

import { PasskeyStore } from './base.js';

import type { PasskeyChallengeRecord, PasskeyUserDescriptor, StoredPasskeyCredential } from './types.js';
import type { AuthIdentifier } from '../auth-api/types.js';

function encodeCredentialId(value: Buffer | string): string {
	return Buffer.isBuffer(value) ? value.toString('base64') : value;
}

function cloneCredential(record: StoredPasskeyCredential): StoredPasskeyCredential {
	return {
		...record,
		credentialId: Buffer.isBuffer(record.credentialId) ? Buffer.from(record.credentialId) : record.credentialId,
		publicKey: Buffer.from(record.publicKey),
		transports: record.transports ? [...record.transports] : undefined
	};
}

export interface MemoryPasskeyStoreOptions {
	resolveUser: (params: { userId?: AuthIdentifier; login?: string }) => Promise<PasskeyUserDescriptor | null>;
	maxCredentials?: number;
	maxChallenges?: number;
}

export class MemoryPasskeyStore extends PasskeyStore {
	private readonly resolveUserFn: MemoryPasskeyStoreOptions['resolveUser'];
	private readonly credentials = new Map<string, StoredPasskeyCredential>();
	private readonly challenges = new Map<string, PasskeyChallengeRecord>();
	private readonly maxCredentials?: number;
	private readonly maxChallenges?: number;

	constructor(options: MemoryPasskeyStoreOptions) {
		super();
		this.resolveUserFn = options.resolveUser;
		this.maxCredentials =
			typeof options.maxCredentials === 'number' &&
			Number.isFinite(options.maxCredentials) &&
			options.maxCredentials > 0
				? Math.floor(options.maxCredentials)
				: undefined;
		this.maxChallenges =
			typeof options.maxChallenges === 'number' &&
			Number.isFinite(options.maxChallenges) &&
			options.maxChallenges > 0
				? Math.floor(options.maxChallenges)
				: undefined;
	}

	public override async resolveUser(params: {
		userId?: AuthIdentifier;
		login?: string;
	}): Promise<PasskeyUserDescriptor | null> {
		return this.resolveUserFn(params);
	}

	public override async listUserCredentials(userId: AuthIdentifier): Promise<StoredPasskeyCredential[]> {
		const normalizedUserId = normalizeComparableUserId(userId);
		return [...this.credentials.values()]
			.filter((record) => normalizeComparableUserId(record.userId) === normalizedUserId)
			.map((record) => cloneCredential(record));
	}

	public override async deleteCredential(credentialId: Buffer | string): Promise<boolean> {
		const key = encodeCredentialId(credentialId);
		return this.credentials.delete(key);
	}

	public override async findCredentialById(credentialId: Buffer): Promise<StoredPasskeyCredential | null> {
		const record = this.credentials.get(encodeCredentialId(credentialId));
		return record ? cloneCredential(record) : null;
	}

	public override async saveCredential(record: StoredPasskeyCredential): Promise<void> {
		this.credentials.set(encodeCredentialId(record.credentialId), {
			...record,
			userId: normalizeComparableUserId(record.userId),
			credentialId: Buffer.isBuffer(record.credentialId) ? Buffer.from(record.credentialId) : record.credentialId,
			transports: record.transports ? [...record.transports] : undefined
		});
		this.enforceCredentialCapacity();
	}

	public override async updateCredentialCounter(credentialId: Buffer, counter: number): Promise<void> {
		const key = encodeCredentialId(credentialId);
		const existing = this.credentials.get(key);
		if (existing) {
			existing.counter = counter;
		}
	}

	public override async saveChallenge(record: PasskeyChallengeRecord): Promise<void> {
		this.challenges.set(record.challenge, {
			challenge: record.challenge,
			action: record.action,
			userId: record.userId !== undefined ? normalizeComparableUserId(record.userId) : undefined,
			login: record.login ?? undefined,
			expiresAt: record.expiresAt
		});
		this.enforceChallengeCapacity();
	}

	public override async getChallenge(challenge: string): Promise<PasskeyChallengeRecord | null> {
		const record = this.challenges.get(challenge);
		return record ? { ...record } : null;
	}

	public override async consumeChallenge(challenge: string): Promise<PasskeyChallengeRecord | null> {
		const record = this.challenges.get(challenge);
		if (!record) {
			return null;
		}
		this.challenges.delete(challenge);
		return { ...record };
	}

	public override async cleanupChallenges(now: Date): Promise<void> {
		for (const [challenge, record] of this.challenges.entries()) {
			if (record.expiresAt && new Date(record.expiresAt) <= now) {
				this.challenges.delete(challenge);
			}
		}
	}

	private enforceCredentialCapacity(): void {
		if (!this.maxCredentials) {
			return;
		}
		while (this.credentials.size > this.maxCredentials) {
			const oldest = this.credentials.keys().next().value;
			if (!oldest) {
				return;
			}
			this.credentials.delete(oldest);
		}
	}

	private enforceChallengeCapacity(): void {
		if (!this.maxChallenges) {
			return;
		}
		while (this.challenges.size > this.maxChallenges) {
			const oldest = this.challenges.keys().next().value;
			if (!oldest) {
				return;
			}
			this.challenges.delete(oldest);
		}
	}
}
