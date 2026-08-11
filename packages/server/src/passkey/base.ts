import type {
	PasskeyChallengeRecord,
	PasskeyStorageAdapter,
	PasskeyUserDescriptor,
	StoredPasskeyCredential
} from './types.js';
import type { AuthIdentifier } from '../auth-api/types.js';

/** Base contract for passkey credential/challenge persistence backends. */
export abstract class PasskeyStore implements PasskeyStorageAdapter {
	/** Resolve a passkey user descriptor by id/login. */
	public abstract resolveUser(params: {
		userId?: AuthIdentifier;
		login?: string;
	}): Promise<PasskeyUserDescriptor | null>;
	/** List passkey credentials for a user. */
	public abstract listUserCredentials(userId: AuthIdentifier): Promise<StoredPasskeyCredential[]>;
	/** Delete a credential by binary/base64url id. */
	public abstract deleteCredential(credentialId: Buffer | string): Promise<boolean>;
	/** Find a credential by binary id. */
	public abstract findCredentialById(credentialId: Buffer): Promise<StoredPasskeyCredential | null>;
	/** Save a credential record. */
	public abstract saveCredential(record: StoredPasskeyCredential): Promise<void>;
	/** Update signature counter for a credential. */
	public abstract updateCredentialCounter(credentialId: Buffer, counter: number): Promise<void>;
	/** Save a challenge record. */
	public abstract saveChallenge(record: PasskeyChallengeRecord): Promise<void>;
	/** Read a challenge without consuming it. */
	public abstract getChallenge(challenge: string): Promise<PasskeyChallengeRecord | null>;
	/** Consume and return a challenge. */
	public abstract consumeChallenge(challenge: string): Promise<PasskeyChallengeRecord | null>;
	/** Cleanup expired challenges. */
	public abstract cleanupChallenges(now: Date): Promise<void>;
}
