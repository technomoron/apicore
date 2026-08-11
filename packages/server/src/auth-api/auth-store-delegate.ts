import { normalizeTokenIdentityQuery, type TokenIdentityQuery } from './token-query.js';

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

export abstract class AuthStoreDelegate<UserAttributes, PublicUserShape> implements AuthAdapter<
	UserAttributes,
	PublicUserShape
> {
	protected adapter!: AuthAdapter<UserAttributes, PublicUserShape>;

	public async getUser(identifier: AuthIdentifier): Promise<UserAttributes | null> {
		return this.adapter.getUser(identifier);
	}

	public getUserPasswordHash(user: UserAttributes): string {
		return this.adapter.getUserPasswordHash(user);
	}

	public getUserId(user: UserAttributes): AuthIdentifier {
		return this.adapter.getUserId(user);
	}

	public filterUser(user: UserAttributes): PublicUserShape {
		return this.adapter.filterUser(user);
	}

	public async verifyPassword(password: string, hash: string): Promise<boolean> {
		return this.adapter.verifyPassword(password, hash);
	}

	public async storeToken(data: Token): Promise<void> {
		return this.adapter.storeToken(data);
	}

	public async getToken(query: TokenIdentityQuery, opts?: { includeExpired?: boolean }): Promise<Token | null> {
		return this.adapter.getToken(normalizeTokenIdentityQuery(query), opts);
	}

	public async deleteToken(query: TokenIdentityQuery): Promise<number> {
		return this.adapter.deleteToken(normalizeTokenIdentityQuery(query));
	}

	public async updateToken(updates: Partial<Token> & { refreshToken: string }): Promise<boolean> {
		return this.adapter.updateToken?.(updates) ?? false;
	}

	public async listTokens(
		userId: string | number,
		opts?: { limit?: number; offset?: number; includeExpired?: boolean }
	): Promise<Token[]> {
		return this.adapter.listTokens?.(userId, opts) ?? [];
	}

	public async createPasskeyChallenge(params: PasskeyChallengeParams): Promise<PasskeyChallenge> {
		if (!this.adapter.createPasskeyChallenge) throw new Error('Passkey storage is not configured');
		return this.adapter.createPasskeyChallenge(params);
	}

	public async getPasskeyChallenge(challenge: string): Promise<PasskeyChallengeRecord | null> {
		return this.adapter.getPasskeyChallenge?.(challenge) ?? null;
	}

	public async verifyPasskeyResponse(params: PasskeyVerificationParams): Promise<PasskeyVerificationResult> {
		if (!this.adapter.verifyPasskeyResponse) throw new Error('Passkey storage is not configured');
		return this.adapter.verifyPasskeyResponse(params);
	}

	public async listUserCredentials(userId: AuthIdentifier): Promise<StoredPasskeyCredential[]> {
		if (!this.adapter.listUserCredentials) throw new Error('Passkey storage is not configured');
		return this.adapter.listUserCredentials(userId);
	}

	public async deletePasskeyCredential(credentialId: Buffer | string): Promise<boolean> {
		if (!this.adapter.deletePasskeyCredential) throw new Error('Passkey storage is not configured');
		return this.adapter.deletePasskeyCredential(credentialId);
	}

	public async getClient(clientId: string): Promise<OAuthClient | null> {
		return this.adapter.getClient?.(clientId) ?? null;
	}

	public async verifyClientSecret(client: OAuthClient, clientSecret: string | null): Promise<boolean> {
		if (!this.adapter.verifyClientSecret) throw new Error('OAuth storage is not configured');
		return this.adapter.verifyClientSecret(client, clientSecret);
	}

	public async createAuthCode(request: AuthCodeRequest): Promise<AuthCodeData> {
		if (!this.adapter.createAuthCode) throw new Error('OAuth storage is not configured');
		return this.adapter.createAuthCode(request);
	}

	public async consumeAuthCode(code: string, clientId: string): Promise<AuthCodeData | null> {
		return this.adapter.consumeAuthCode?.(code, clientId) ?? null;
	}

	public async canImpersonate(params: {
		realUserId: AuthIdentifier;
		effectiveUserId: AuthIdentifier;
	}): Promise<boolean> {
		return this.adapter.canImpersonate?.(params) ?? false;
	}
}
