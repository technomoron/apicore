import { randomUUID } from 'node:crypto';

import jwt from 'jsonwebtoken';

import type { Token } from './types.js';
import type { DecodeOptions, SignOptions, VerifyOptions } from 'jsonwebtoken';

export interface JwtSignResult {
	success: boolean;
	token?: string;
	error?: string;
}

export type JwtSignPayload = string | Buffer | Record<string, unknown>;

export interface JwtVerifyResult<T> {
	success: boolean;
	data?: T;
	expired?: boolean;
	error?: string;
}

export interface JwtDecodeResult<T> {
	success: boolean;
	data?: T;
	error?: string;
}

function normalizeScope(scope: Token['scope'] | string): string[] | undefined {
	if (!scope) {
		return undefined;
	}
	if (Array.isArray(scope)) {
		return scope.filter((entry) => typeof entry === 'string' && entry.length > 0);
	}
	return scope
		.split(/\s+/)
		.map((entry) => entry.trim())
		.filter((entry) => entry.length > 0);
}

function normalizeRefreshTtlSeconds(value: unknown): number | undefined {
	if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
		return Math.floor(value);
	}
	if (typeof value === 'string') {
		const parsed = Number(value);
		if (Number.isFinite(parsed) && parsed > 0) {
			return Math.floor(parsed);
		}
	}
	return undefined;
}

function requireTokenString(value: unknown, field: 'refreshToken' | 'accessToken'): string {
	if (typeof value !== 'string' || value.length === 0) {
		throw new Error(`${field} is required`);
	}
	return value;
}

function requireUserId(value: unknown): string {
	if (value === undefined || value === null) {
		throw new Error('userId is required');
	}
	return String(value);
}

function normalizeTokenDate(value: unknown, fallback: Date, field: string): Date {
	const date = value ? new Date(value as string | number | Date) : fallback;
	if (Number.isNaN(date.getTime())) {
		throw new Error(`Invalid token ${field} value: ${String(value)}`);
	}
	return date;
}

function optionalString(value: unknown, fallback = ''): string {
	return typeof value === 'string' ? value : fallback;
}

function optionalNonEmptyString(value: unknown): string | undefined {
	return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function tokenStatus(input: Partial<Token>, expires: Date): Token['status'] {
	if (input.status === 'revoked') {
		return 'revoked';
	}
	return expires.getTime() < Date.now() ? 'expired' : 'active';
}

function normalizeTokenInternal(input: Partial<Token> & { scope?: string | string[] }): Token {
	const refreshToken = requireTokenString(input.refreshToken, 'refreshToken');
	const accessToken = requireTokenString(input.accessToken, 'accessToken');
	const userId = requireUserId(input.userId);
	const ruid = input.ruid === undefined || input.ruid === null ? undefined : String(input.ruid);
	const expires = normalizeTokenDate(input.expires, new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), 'expiry');
	const issuedAt = normalizeTokenDate(input.issuedAt, new Date(), 'issuedAt');
	const lastSeenAt = input.lastSeenAt ? new Date(input.lastSeenAt) : issuedAt;
	const scope = normalizeScope(input.scope);
	const refreshTtlSeconds = normalizeRefreshTtlSeconds(input.refreshTtlSeconds);
	const status = tokenStatus(input, expires);
	const sessionCookie = typeof input.sessionCookie === 'boolean' ? input.sessionCookie : false;

	return {
		accessToken,
		refreshToken,
		sessionId:
			typeof input.sessionId === 'string' && input.sessionId.trim().length > 0
				? input.sessionId.trim()
				: randomUUID(),
		userId,
		clientId: optionalNonEmptyString(input.clientId),
		domain: optionalString(input.domain),
		fingerprint: optionalString(input.fingerprint),
		label: optionalString(input.label),
		browser: optionalString(input.browser),
		device: optionalString(input.device),
		ip: optionalString(input.ip),
		os: optionalString(input.os),
		loginType: optionalNonEmptyString(input.loginType),
		scope,
		refreshTtlSeconds,
		expires,
		issuedAt,
		lastSeenAt,
		status,
		ruid,
		sessionCookie
	};
}

export function hasTokenLookupField(query: Partial<Token>): boolean {
	return Boolean(query.refreshToken || query.accessToken || query.sessionId || query.userId !== undefined);
}

export function assertTokenLookupField(query: Partial<Token>): void {
	if (!hasTokenLookupField(query)) {
		throw new Error('At least one token lookup field must be provided');
	}
}

export function hasTokenDeleteField(query: Partial<Token>): boolean {
	return hasTokenLookupField(query) || Boolean(query.clientId);
}

/** Base contract for token/session persistence backends plus shared JWT helpers. */
export abstract class TokenStore {
	/** Create/persist a token record. */
	public abstract save(record: Token): Promise<void>;
	/** Read a token record by partial query. */
	public abstract get(query: Partial<Token>, opts?: { includeExpired?: boolean }): Promise<Token | null>;
	/** Delete token records matching a partial query. */
	public abstract delete(query: Partial<Token>): Promise<number>;
	/** Update a token identified by refresh token. */
	public abstract update(update: Partial<Token> & { refreshToken: string }): Promise<boolean>;
	/** List tokens for a specific user. */
	public abstract list(
		userId: string | number,
		opts?: { limit?: number; offset?: number; includeExpired?: boolean }
	): Promise<Token[]>;
	/** Close underlying resources. */
	public abstract close(): Promise<void>;

	// Instance helpers

	public normalizeToken(token: Partial<Token>): Token {
		return normalizeTokenInternal(token);
	}

	// JWT helpers live on TokenStore so every adapter automatically exposes
	// signing/verification without additional wiring.
	public jwtSign(
		payload: JwtSignPayload,
		secret: string,
		expiresInSeconds: number,
		options?: SignOptions
	): JwtSignResult {
		const opts: SignOptions = {
			...(options ?? {}),
			expiresIn: expiresInSeconds
		};
		try {
			const token = jwt.sign(payload, secret, opts);
			return { success: true, token };
		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : String(error)
			};
		}
	}

	public jwtVerify<T>(token: string, secret: string, options?: VerifyOptions): JwtVerifyResult<T> {
		try {
			const data = jwt.verify(token, secret, {
				algorithms: ['HS256', 'HS384', 'HS512'],
				...(options ?? {})
			}) as T;
			return { success: true, data };
		} catch (error) {
			if (error instanceof jwt.TokenExpiredError) {
				return {
					success: false,
					expired: true,
					error: 'Token expired'
				};
			}
			return {
				success: false,
				expired: false,
				error: error instanceof Error ? error.message : String(error)
			};
		}
	}

	public jwtDecode<T>(token: string, options?: DecodeOptions): JwtDecodeResult<T> {
		try {
			const data = jwt.decode(token, options ?? {}) as T;
			if (data === null) {
				return { success: false, error: 'Invalid token format' };
			}
			return { success: true, data };
		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : String(error)
			};
		}
	}
}
