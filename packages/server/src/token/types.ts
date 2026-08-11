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
