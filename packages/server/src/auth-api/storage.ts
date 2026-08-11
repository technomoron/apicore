import type { AuthAdapter, AuthIdentifier } from './types.js';
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

// Handy base you can extend when wiring a real auth adapter. Every method
// throws by default so unimplemented hooks fail loudly.
export class BaseAuthAdapter<UserRow = unknown, SafeUser = unknown> implements AuthAdapter<UserRow, SafeUser> {
	// Override to load a user record by identifier
	async getUser(identifier: AuthIdentifier): Promise<UserRow | null> {
		void identifier;
		return null;
	}

	// Override to return the stored password hash for the user
	getUserPasswordHash(user: UserRow): string {
		void user;
		throw new Error('Auth storage not configured');
	}

	// Override to expose the canonical user identifier
	getUserId(user: UserRow): AuthIdentifier {
		void user;
		throw new Error('Auth storage not configured');
	}

	// Override to strip sensitive fields from the user record
	filterUser(user: UserRow): SafeUser {
		return user as unknown as SafeUser;
	}

	// Override to validate a raw password against the stored hash
	async verifyPassword(password: string, hash: string): Promise<boolean> {
		void password;
		void hash;
		throw new Error('Auth storage not configured');
	}

	// Override to persist newly issued tokens
	async storeToken(data: Token): Promise<void> {
		void data;
		throw new Error('Auth storage not configured');
	}

	// Override to look up a stored token by query
	async getToken(
		query: Partial<Omit<Token, 'userId' | 'ruid'>> & {
			userId?: string | number;
			ruid?: string | number;
		},
		opts?: { includeExpired?: boolean }
	): Promise<Token | null> {
		void query;
		void opts;
		return null;
	}

	// Override to remove stored tokens that match the query
	async deleteToken(
		query: Partial<Omit<Token, 'userId' | 'ruid'>> & {
			userId?: string | number;
			ruid?: string | number;
		}
	): Promise<number> {
		void query;
		return 0;
	}

	// Override to update metadata for an existing refresh token
	async updateToken(updates: Partial<Token> & { refreshToken: string }): Promise<boolean> {
		void updates;
		return false;
	}

	// Override to list stored session tokens for a user
	async listTokens(
		userId: string | number,
		opts?: { limit?: number; offset?: number; includeExpired?: boolean }
	): Promise<Token[]> {
		void userId;
		void opts;
		return [];
	}

	// Override to create a new passkey challenge record
	async createPasskeyChallenge(params: PasskeyChallengeParams): Promise<PasskeyChallenge> {
		void params;
		throw new Error('Auth storage not configured');
	}

	// Override to read a passkey challenge without consuming it
	async getPasskeyChallenge(challenge: string): Promise<PasskeyChallengeRecord | null> {
		void challenge;
		return null;
	}

	// Override to verify an incoming WebAuthn response
	async verifyPasskeyResponse(params: PasskeyVerificationParams): Promise<PasskeyVerificationResult> {
		void params;
		throw new Error('Auth storage not configured');
	}

	// Override to list passkey credentials for a user
	async listUserCredentials(userId: AuthIdentifier): Promise<StoredPasskeyCredential[]> {
		void userId;
		throw new Error('Auth storage not configured');
	}

	// Override to delete a passkey credential
	async deletePasskeyCredential(credentialId: Buffer | string): Promise<boolean> {
		void credentialId;
		throw new Error('Auth storage not configured');
	}

	// Override to fetch an OAuth client by identifier
	async getClient(clientId: string): Promise<OAuthClient | null> {
		void clientId;
		return null;
	}

	// Override to compare a provided client secret against storage
	async verifyClientSecret(client: OAuthClient, clientSecret: string | null): Promise<boolean> {
		void client;
		void clientSecret;
		throw new Error('Auth storage not configured');
	}

	// Override to create a new authorization code entry
	async createAuthCode(request: AuthCodeRequest): Promise<AuthCodeData> {
		void request;
		throw new Error('Auth storage not configured');
	}

	// Override to consume and invalidate an authorization code
	async consumeAuthCode(code: string, clientId: string): Promise<AuthCodeData | null> {
		void code;
		void clientId;
		return null;
	}

	// Override to decide if a real user may impersonate another user
	async canImpersonate(params: { realUserId: AuthIdentifier; effectiveUserId: AuthIdentifier }): Promise<boolean> {
		void params;
		return false;
	}
}

export const nullAuthAdapter: AuthAdapter<unknown, unknown> = new BaseAuthAdapter();
