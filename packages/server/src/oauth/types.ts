// OAuth-specific contracts kept alongside the OAuth module.

import type { AuthIdentifier } from '../auth-api/types.js';

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
