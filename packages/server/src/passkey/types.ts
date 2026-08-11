import type { AuthIdentifier } from '../auth-api/types.js';
import type { Token, TokenPair } from '../token/types.js';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';

export type CredentialDeviceType = 'singleDevice' | 'multiDevice';

export interface PasskeyServiceConfig {
	rpId: string;
	rpName: string;
	origins: string[];
	timeoutMs: number;
	userVerification?: 'preferred' | 'required' | 'discouraged';
	/**
	 * When enabled, PasskeyService emits additional diagnostic logs during registration/authentication.
	 * Defaults to false.
	 */
	debug?: boolean;
}

export interface PasskeyChallengeRecord {
	challenge: string;
	action: 'register' | 'authenticate';
	userId?: AuthIdentifier;
	login?: string;
	expiresAt: Date;
}

export interface PasskeyUserDescriptor {
	id: AuthIdentifier;
	login: string;
	displayName: string;
}

export interface StoredPasskeyCredential {
	userId: AuthIdentifier;
	credentialId: Buffer;
	publicKey: Buffer;
	counter: number;
	transports?: AuthenticatorTransportFuture[];
	backedUp: boolean;
	deviceType: CredentialDeviceType;
	label?: string;
	createdDomain?: string;
	createdUserAgent?: string;
	createdBrowser?: string;
	createdOs?: string;
	createdDevice?: string;
	createdIp?: string;
	createdAt?: Date;
	updatedAt?: Date;
}

export interface PasskeyStorageAdapter {
	resolveUser(params: { userId?: AuthIdentifier; login?: string }): Promise<PasskeyUserDescriptor | null>;
	listUserCredentials(userId: AuthIdentifier): Promise<StoredPasskeyCredential[]>;
	deleteCredential(credentialId: Buffer | string): Promise<boolean>;
	findCredentialById(credentialId: Buffer): Promise<StoredPasskeyCredential | null>;
	saveCredential(record: StoredPasskeyCredential): Promise<void>;
	updateCredentialCounter(credentialId: Buffer, counter: number): Promise<void>;
	saveChallenge(record: PasskeyChallengeRecord): Promise<void>;
	getChallenge?(challenge: string): Promise<PasskeyChallengeRecord | null>;
	consumeChallenge(challenge: string): Promise<PasskeyChallengeRecord | null>;
	cleanupChallenges?(now: Date): Promise<void>;
}

export interface PasskeyChallengeParams {
	action: 'register' | 'authenticate';
	login?: string;
	userId?: AuthIdentifier;
}

export interface PasskeyChallenge extends Record<string, unknown> {
	challenge: string;
	expiresAt?: string | number | Date;
	userId?: AuthIdentifier;
}

export interface PasskeyVerificationParams extends Partial<Omit<Token, 'userId'>> {
	expectedChallenge: string;
	login?: string;
	response: Record<string, unknown>;
	userId?: AuthIdentifier;
	userAgent?: string;
}

export interface PasskeyVerificationResult extends Record<string, unknown> {
	action?: 'register' | 'authenticate';
	/**
	 * Base64URL id of the credential written by a successful `register`
	 * verification. Lets the caller roll the credential back if a later
	 * authorization check rejects the request.
	 */
	credentialId?: string;
	login?: string;
	tokens?: TokenPair;
	userId?: AuthIdentifier;
	verified: boolean;
}
