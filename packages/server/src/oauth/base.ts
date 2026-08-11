import type { AuthCode, OAuthClient } from './types.js';

/** Base contract for OAuth client/auth-code persistence backends. */
export abstract class OAuthStore {
	/** Fetch an OAuth client by id. */
	public abstract getClient(clientId: string): Promise<OAuthClient | null>;
	/** Create an OAuth client. */
	public abstract createClient(input: OAuthClient): Promise<OAuthClient>;
	/** Verify an OAuth client secret. */
	public abstract verifyClientSecret(clientId: string, secret: string | null): Promise<boolean>;
	/** Persist an authorization code. */
	public abstract createAuthCode(code: AuthCode): Promise<void>;
	/** Consume an authorization code once. When clientId is provided, only consume if it matches. */
	public abstract consumeAuthCode(code: string, clientId?: string): Promise<AuthCode | null>;
	/** Close underlying resources. */
	public abstract close(): Promise<void>;
}

export type { OAuthClient, AuthCode } from './types.js';
