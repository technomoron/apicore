import { randomUUID } from 'node:crypto';

import { PasskeyService } from '../passkey/service.js';

import type { AuthAdapter, AuthIdentifier } from './types.js';
import type { OAuthStore } from '../oauth/base.js';
import type { AuthCodeData, AuthCodeRequest, OAuthClient } from '../oauth/types.js';
import type { PasskeyStore } from '../passkey/base.js';
import type {
	PasskeyChallenge,
	PasskeyChallengeParams,
	PasskeyChallengeRecord,
	PasskeyServiceConfig,
	StoredPasskeyCredential,
	PasskeyVerificationParams,
	PasskeyVerificationResult
} from '../passkey/types.js';
import type { TokenStore } from '../token/base.js';
import type { Token } from '../token/types.js';
import type { UserStore } from '../user/base.js';

interface PasskeyAdapterOptions {
	store: PasskeyStore;
	config: PasskeyServiceConfig;
}

export interface AuthAdapterOptions<UserRow, PublicUser> {
	userStore: UserStore<UserRow, PublicUser>;
	tokenStore: TokenStore;
	passkeys?: PasskeyAdapterOptions | PasskeyService;
	oauthStore?: OAuthStore;
	canImpersonate?: (params: {
		realUserId: AuthIdentifier;
		effectiveUserId: AuthIdentifier;
	}) => boolean | Promise<boolean>;
}

export class CompositeAuthAdapter<UserRow, PublicUser> implements AuthAdapter<UserRow, PublicUser> {
	private readonly userStore: UserStore<UserRow, PublicUser>;
	private readonly tokenStore: TokenStore;
	private readonly oauthStore?: OAuthStore;
	private readonly passkeyService?: PasskeyService;
	private readonly canImpersonateFn?: (params: {
		realUserId: AuthIdentifier;
		effectiveUserId: AuthIdentifier;
	}) => boolean | Promise<boolean>;

	constructor(options: AuthAdapterOptions<UserRow, PublicUser>) {
		this.userStore = options.userStore;
		this.tokenStore = options.tokenStore;
		this.oauthStore = options.oauthStore;
		this.canImpersonateFn = options.canImpersonate;
		if (options.passkeys instanceof PasskeyService) {
			this.passkeyService = options.passkeys;
		} else if (options.passkeys) {
			this.passkeyService = new PasskeyService(options.passkeys.config, options.passkeys.store);
		}
	}

	public async getUser(identifier: AuthIdentifier): Promise<UserRow | null> {
		return this.userStore.findUser(identifier);
	}

	public getUserPasswordHash(user: UserRow): string {
		return this.userStore.getPasswordHash(user) ?? '';
	}

	public getUserId(user: UserRow): AuthIdentifier {
		return this.userStore.getUserId(user);
	}

	public filterUser(user: UserRow): PublicUser {
		return this.userStore.toPublic(user);
	}

	public async verifyPassword(password: string, hash: string): Promise<boolean> {
		return this.userStore.verifyPassword(password, hash);
	}

	public async storeToken(data: Token): Promise<void> {
		return this.tokenStore.save(data);
	}

	public async getToken(query: Partial<Token>, opts?: { includeExpired?: boolean }): Promise<Token | null> {
		return this.tokenStore.get(query, opts);
	}

	public async deleteToken(query: Partial<Token>): Promise<number> {
		return this.tokenStore.delete(query);
	}

	public async updateToken(updates: Partial<Token> & { refreshToken: string }): Promise<boolean> {
		return this.tokenStore.update(updates);
	}

	public async listTokens(
		userId: string | number,
		opts?: { limit?: number; offset?: number; includeExpired?: boolean }
	): Promise<Token[]> {
		return this.tokenStore.list(userId, opts);
	}

	public async createPasskeyChallenge(params: PasskeyChallengeParams): Promise<PasskeyChallenge> {
		if (!this.passkeyService) {
			throw new Error('Passkey storage is not configured');
		}
		return this.passkeyService.createChallenge(params);
	}

	public async getPasskeyChallenge(challenge: string): Promise<PasskeyChallengeRecord | null> {
		if (!this.passkeyService) {
			return null;
		}
		return this.passkeyService.getChallenge(challenge);
	}

	public async verifyPasskeyResponse(params: PasskeyVerificationParams): Promise<PasskeyVerificationResult> {
		if (!this.passkeyService) {
			throw new Error('Passkey storage is not configured');
		}
		return this.passkeyService.verifyResponse(params);
	}

	public async listUserCredentials(userId: AuthIdentifier): Promise<StoredPasskeyCredential[]> {
		if (!this.passkeyService) {
			throw new Error('Passkey storage is not configured');
		}
		return this.passkeyService.listUserCredentials(userId);
	}

	public async deletePasskeyCredential(credentialId: Buffer | string): Promise<boolean> {
		if (!this.passkeyService) {
			throw new Error('Passkey storage is not configured');
		}
		return this.passkeyService.deleteCredential(credentialId);
	}

	public async getClient(clientId: string): Promise<OAuthClient | null> {
		if (!this.oauthStore) {
			return null;
		}
		return this.oauthStore.getClient(clientId);
	}

	public async verifyClientSecret(client: OAuthClient, clientSecret: string | null): Promise<boolean> {
		if (!this.oauthStore) {
			throw new Error('OAuth storage is not configured');
		}
		return this.oauthStore.verifyClientSecret(client.clientId, clientSecret);
	}

	public async createAuthCode(request: AuthCodeRequest): Promise<AuthCodeData> {
		if (!this.oauthStore) {
			throw new Error('OAuth storage is not configured');
		}
		const expiresAt = new Date(Date.now() + (request.expiresInSeconds ?? 300) * 1000);
		const code = request.code ?? randomUUID();
		await this.oauthStore.createAuthCode({
			code,
			clientId: request.clientId,
			userId: request.userId,
			scope: request.scope,
			redirectUri: request.redirectUri,
			codeChallenge: request.codeChallenge,
			codeChallengeMethod: request.codeChallengeMethod,
			expiresAt,
			metadata: request.metadata
		});
		return {
			code,
			clientId: request.clientId,
			userId: request.userId,
			redirectUri: request.redirectUri,
			scope: request.scope ?? [],
			codeChallenge: request.codeChallenge,
			codeChallengeMethod: request.codeChallengeMethod,
			expiresAt,
			metadata: request.metadata
		};
	}

	public async consumeAuthCode(code: string, clientId: string): Promise<AuthCodeData | null> {
		if (!this.oauthStore) {
			return null;
		}
		const consumed = await this.oauthStore.consumeAuthCode(code, clientId);
		if (!consumed) {
			return null;
		}
		return consumed;
	}

	public async canImpersonate(params: {
		realUserId: AuthIdentifier;
		effectiveUserId: AuthIdentifier;
	}): Promise<boolean> {
		if (this.canImpersonateFn) {
			return !!(await this.canImpersonateFn(params));
		}
		return String(params.realUserId) === String(params.effectiveUserId);
	}
}
