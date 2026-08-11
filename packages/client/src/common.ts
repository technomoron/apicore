/**
 * Shared type definitions used by both apicore-server and apicore-client.
 * This file contains only `type`/`interface` declarations — no runtime code.
 * Both packages reference these types via `import type` so API response
 * payload shapes have one canonical source.
 */

export type AuthIdentifier = string | number;
export type SafeUser = Record<string, unknown>;

export interface ApiResponse<T = unknown> {
	success: boolean;
	code: number;
	message: string;
	data: T | null;
	errors: Record<string, string>;
}

export interface ApiPingRes {
	success: boolean;
	status: string;
	apiVersion: string;
	minClientVersion: string;
	uptimeSec: number;
	startedAt: number;
	timestamp: string;
}

export interface ApiRefreshRes {
	accessToken?: string;
	refreshToken?: string;
}

export interface ApiLoginRes<User = SafeUser> extends ApiRefreshRes {
	user?: User;
}

export interface ApiMeRes<User = SafeUser> {
	user: User;
	ruser?: User | null;
}

export interface ApiLogoutRes {
	revoked: number;
}

export type TokenStatus = 'active' | 'expired' | 'revoked';

export interface Token {
	accessToken: string;
	refreshToken: string;
	sessionId?: string;
	userId: string;
	expires?: Date;
	issuedAt?: Date;
	lastSeenAt?: Date;
	status?: TokenStatus;
	ruid?: string;
	clientId?: string;
	/**
	 * Optional session partition key. Token stores may use `domain` and `fingerprint`
	 * to replace previous sessions that match the same bucket.
	 */
	domain?: string;
	/**
	 * Optional device/session fingerprint used together with `domain` for session bucketing.
	 */
	fingerprint?: string;
	label?: string;
	browser?: string;
	device?: string;
	ip?: string;
	os?: string;
	scope?: string[];
	loginType?: string;
	refreshTtlSeconds?: number;
	sessionCookie?: boolean;
}

export interface TokenPair {
	accessToken: string;
	refreshToken: string;
}

export interface SessionInfo {
	sessionId: string;
	current: boolean;
	tokenHint?: string;
	expires?: string;
	issuedAt?: string;
	lastSeenAt?: string;
	status?: TokenStatus;
	clientId?: string;
	domain?: string;
	fingerprint?: string;
	label?: string;
	browser?: string;
	device?: string;
	ip?: string;
	os?: string;
	scope?: string[];
	loginType?: string;
	sessionCookie?: boolean;
}

export interface ApiSessionsRes {
	sessions: SessionInfo[];
}

export interface ApiRevokeSessionRes {
	revoked: number;
}

export interface ApiPasskeyChallengeRes {
	challenge: string;
	[key: string]: unknown;
}

export interface ApiPasskeyVerifyRes<User = SafeUser> extends ApiLoginRes<User> {}

export interface ApiPasskeyCredential {
	id: string;
	transports?: string[];
	backedUp: boolean;
	deviceType: 'singleDevice' | 'multiDevice';
	createdAt?: string;
	updatedAt?: string;
}

export interface ApiPasskeyListRes {
	credentials: ApiPasskeyCredential[];
}

export interface ApiPasskeyDeleteRes {
	deleted: boolean;
}

export interface OAuthClient {
	clientId: string;
	clientSecret?: string;
	hasSecret?: boolean;
	firstParty?: boolean;
	metadata?: Record<string, unknown>;
	name?: string;
	redirectUris: string[];
	scope?: string[];
}

export interface AuthCodeData {
	code: string;
	clientId: string;
	codeChallenge?: string;
	codeChallengeMethod?: 'plain' | 'S256';
	expiresAt: Date;
	metadata?: Record<string, unknown>;
	redirectUri?: string;
	scope?: string[];
	userId: AuthIdentifier;
}

export type AuthCode = AuthCodeData;

export type AuthCodeRequest = Omit<AuthCodeData, 'code' | 'expiresAt'> & {
	code?: string;
	expiresInSeconds?: number;
};

export interface OAuthStartParams {
	provider: string;
	redirectUri?: string;
	scope?: string | string[];
	state?: string;
	extras?: Record<string, unknown>;
}

export interface OAuthStartResult extends Record<string, unknown> {
	url: string;
	state?: string;
	codeVerifier?: string;
}

export type ApiOAuthStartRes = OAuthStartResult;

export interface OAuthCallbackParams {
	provider: string;
	query: Record<string, string | string[]>;
	body: Record<string, unknown>;
}

export interface OAuthCallbackResult<PublicUser> extends Record<string, unknown> {
	user: PublicUser;
	tokens?: {
		accessToken: string;
		refreshToken: string;
	};
}

export type ApiOAuthCallbackRes<User = SafeUser> = OAuthCallbackResult<User>;

export interface ApiOAuthAuthorizeRes {
	code: string;
	redirectUri: string;
	state?: string;
}

export interface ApiOAuthTokenRes {
	access_token: string;
	refresh_token: string;
	token_type: 'Bearer';
	expires_in: number;
	scope: string;
	client_id: string;
}
