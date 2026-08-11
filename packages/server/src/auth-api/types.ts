// Shared auth-related types that stay free of storage driver imports.
import type { AuthCodeData, AuthCodeRequest, OAuthClient } from '../oauth/types.js';
import type {
	PasskeyChallenge,
	PasskeyChallengeParams,
	PasskeyChallengeRecord,
	PasskeyVerificationParams,
	PasskeyVerificationResult,
	StoredPasskeyCredential
} from '../passkey/types.js';
import type { Token } from '../token/types.js';
export type AuthIdentifier = string | number;

/** @internal */
export interface AuthAdapter<UserRow, SafeUser> {
	getUser(identifier: AuthIdentifier): Promise<UserRow | null>;
	getUserPasswordHash(user: UserRow): string;
	getUserId(user: UserRow): AuthIdentifier;
	filterUser(user: UserRow): SafeUser;
	verifyPassword(password: string, hash: string): Promise<boolean>;
	storeToken(data: Token): Promise<void>;
	getToken(query: Partial<Token>, opts?: { includeExpired?: boolean }): Promise<Token | null>;
	deleteToken(query: Partial<Token>): Promise<number>;
	updateToken?(updates: Partial<Token> & { refreshToken: string }): Promise<boolean>;
	listTokens?(
		userId: string | number,
		opts?: { limit?: number; offset?: number; includeExpired?: boolean }
	): Promise<Token[]>;
	createPasskeyChallenge?(params: PasskeyChallengeParams): Promise<PasskeyChallenge>;
	getPasskeyChallenge?(challenge: string): Promise<PasskeyChallengeRecord | null>;
	verifyPasskeyResponse?(params: PasskeyVerificationParams): Promise<PasskeyVerificationResult>;
	listUserCredentials?(userId: AuthIdentifier): Promise<StoredPasskeyCredential[]>;
	deletePasskeyCredential?(credentialId: Buffer | string): Promise<boolean>;
	getClient?(clientId: string): Promise<OAuthClient | null>;
	verifyClientSecret?(client: OAuthClient, clientSecret: string | null): Promise<boolean>;
	createAuthCode?(request: AuthCodeRequest): Promise<AuthCodeData>;
	consumeAuthCode?(code: string, clientId: string): Promise<AuthCodeData | null>;
	canImpersonate?(params: { realUserId: AuthIdentifier; effectiveUserId: AuthIdentifier }): Promise<boolean>;
}

// Backwards compatibility alias
/** @internal */
export type AuthStorage<UserRow, SafeUser> = AuthAdapter<UserRow, SafeUser>;
