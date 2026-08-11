import { assertTokenLookupField, hasTokenDeleteField, TokenStore } from './base.js';

import type { Token } from './types.js';

function comparableUserId(value: string | number | undefined): string | undefined {
	if (value === undefined) {
		return undefined;
	}
	return String(value);
}

function cloneToken(record: Token): Token {
	return {
		...record,
		scope: record.scope ? [...record.scope] : undefined,
		expires: record.expires ? new Date(record.expires) : undefined,
		issuedAt: record.issuedAt ? new Date(record.issuedAt) : undefined,
		lastSeenAt: record.lastSeenAt ? new Date(record.lastSeenAt) : undefined
	};
}

type TokenQueryPredicate = (record: Token, query: Partial<Token>) => boolean;

const TOKEN_QUERY_PREDICATES: TokenQueryPredicate[] = [
	(record, query) => query.refreshToken === undefined || record.refreshToken === query.refreshToken,
	(record, query) => query.sessionId === undefined || record.sessionId === query.sessionId,
	(record, query) => query.accessToken === undefined || record.accessToken === query.accessToken,
	(record, query) => query.userId === undefined || comparableUserId(record.userId) === comparableUserId(query.userId),
	(record, query) => query.clientId === undefined || record.clientId === query.clientId,
	(record, query) => query.domain === undefined || (record.domain ?? '') === (query.domain ?? ''),
	(record, query) => query.fingerprint === undefined || (record.fingerprint ?? '') === (query.fingerprint ?? ''),
	(record, query) => query.loginType === undefined || record.loginType === (query.loginType ?? undefined),
	(record, query) => query.label === undefined || record.label === query.label
];

function isExpired(record: Token): boolean {
	return (record.expires ? record.expires.getTime() : Infinity) < Date.now();
}

function matchesQuery(record: Token, query: Partial<Token>, includeExpired: boolean): boolean {
	return (
		(includeExpired || !isExpired(record)) && TOKEN_QUERY_PREDICATES.every((predicate) => predicate(record, query))
	);
}

export interface MemoryTokenStoreOptions {
	maxTokens?: number;
}

export class MemoryTokenStore extends TokenStore {
	private readonly tokens = new Map<string, Token>();
	private readonly tokensByUser = new Map<string, Set<string>>();
	private readonly maxTokens?: number;

	constructor(options: MemoryTokenStoreOptions = {}) {
		super();
		this.maxTokens =
			typeof options.maxTokens === 'number' && Number.isFinite(options.maxTokens) && options.maxTokens > 0
				? Math.floor(options.maxTokens)
				: undefined;
	}

	private indexToken(token: Token): void {
		const userId = comparableUserId(token.userId);
		if (!userId) {
			return;
		}
		let userTokens = this.tokensByUser.get(userId);
		if (!userTokens) {
			userTokens = new Set<string>();
			this.tokensByUser.set(userId, userTokens);
		}
		userTokens.add(token.refreshToken);
	}

	private unindexToken(token: Token): void {
		const userId = comparableUserId(token.userId);
		if (!userId) {
			return;
		}
		const userTokens = this.tokensByUser.get(userId);
		if (!userTokens) {
			return;
		}
		userTokens.delete(token.refreshToken);
		if (userTokens.size === 0) {
			this.tokensByUser.delete(userId);
		}
	}

	private removeByRefreshToken(refreshToken: string): void {
		const existing = this.tokens.get(refreshToken);
		if (!existing) {
			return;
		}
		this.unindexToken(existing);
		this.tokens.delete(refreshToken);
	}

	public override async save(record: Token): Promise<void> {
		const stored = this.normalizeToken(record);
		const normalizedUserId = comparableUserId(stored.userId);
		if (!normalizedUserId) {
			throw new Error('userId is required');
		}
		const domainProvided = record.domain !== undefined;
		const fingerprintProvided = record.fingerprint !== undefined;
		const userRefreshTokens = [...(this.tokensByUser.get(normalizedUserId) ?? [])];
		for (const refreshToken of userRefreshTokens) {
			const existing = this.tokens.get(refreshToken);
			if (!existing) {
				continue;
			}
			if (comparableUserId(existing.userId) !== normalizedUserId) {
				continue;
			}
			if (record.clientId && existing.clientId !== record.clientId) {
				continue;
			}
			if (domainProvided && existing.domain !== stored.domain) {
				continue;
			}
			if (fingerprintProvided && existing.fingerprint !== stored.fingerprint) {
				continue;
			}
			this.removeByRefreshToken(existing.refreshToken);
		}
		this.removeByRefreshToken(stored.refreshToken);
		this.tokens.set(stored.refreshToken, stored);
		this.indexToken(stored);
		this.enforceCapacity();
	}

	public override async get(query: Partial<Token>, opts?: { includeExpired?: boolean }): Promise<Token | null> {
		assertTokenLookupField(query);
		const includeExpired = opts?.includeExpired ?? false;
		if (query.refreshToken) {
			const record = this.tokens.get(query.refreshToken);
			return record && matchesQuery(record, query, includeExpired) ? cloneToken(record) : null;
		}
		for (const token of this.tokens.values()) {
			if (matchesQuery(token, query, includeExpired)) {
				return cloneToken(token);
			}
		}
		return null;
	}

	public override async delete(query: Partial<Token>): Promise<number> {
		if (!hasTokenDeleteField(query)) {
			return 0;
		}
		let removed = 0;
		const refreshTokens = [...this.tokens.keys()];
		for (const refreshToken of refreshTokens) {
			const token = this.tokens.get(refreshToken);
			if (token && matchesQuery(token, query, true)) {
				this.removeByRefreshToken(refreshToken);
				removed += 1;
			}
		}
		return removed;
	}

	public override async update(params: Partial<Token> & { refreshToken: string }): Promise<boolean> {
		const token = this.tokens.get(params.refreshToken);
		if (!token) {
			return false;
		}
		if (params.clientId && token.clientId !== params.clientId) {
			return false;
		}

		const merged: Partial<Token> = { ...token };
		const maybeAssign = <K extends keyof Token>(key: K) => {
			const value = params[key];
			if (value !== undefined && value !== null) {
				(merged as Record<string, unknown>)[key] = value as unknown;
			}
		};
		maybeAssign('accessToken');
		maybeAssign('sessionId');
		maybeAssign('expires');
		maybeAssign('issuedAt');
		maybeAssign('lastSeenAt');
		maybeAssign('scope');
		maybeAssign('label');
		maybeAssign('domain');
		maybeAssign('fingerprint');
		maybeAssign('browser');
		maybeAssign('device');
		maybeAssign('ip');
		maybeAssign('os');
		maybeAssign('refreshTtlSeconds');
		maybeAssign('loginType');
		maybeAssign('sessionCookie');

		const normalized = this.normalizeToken(merged);
		const previousUserId = token.userId;
		const previousRefreshToken = token.refreshToken;
		const userChanged = comparableUserId(previousUserId) !== comparableUserId(normalized.userId);
		Object.assign(token, normalized);
		if (userChanged || previousRefreshToken !== token.refreshToken) {
			this.unindexToken({
				...token,
				userId: previousUserId,
				refreshToken: previousRefreshToken
			});
			this.indexToken(token);
			if (previousRefreshToken !== token.refreshToken) {
				this.tokens.delete(previousRefreshToken);
				this.tokens.set(token.refreshToken, token);
			}
		}
		return true;
	}

	public override async list(
		userId: string | number,
		opts: {
			limit?: number;
			offset?: number;
			includeExpired?: boolean;
		} = {}
	): Promise<Token[]> {
		const includeExpired = opts.includeExpired ?? false;
		const normalizedUserId = comparableUserId(userId);
		const userRefreshTokens = normalizedUserId ? [...(this.tokensByUser.get(normalizedUserId) ?? [])] : [];
		const filtered = userRefreshTokens
			.map((refreshToken) => this.tokens.get(refreshToken))
			.filter((token): token is Token => Boolean(token))
			.filter((token) => matchesQuery(token, { userId: normalizedUserId }, includeExpired));
		const offset = opts.offset ?? 0;
		const limit = opts.limit ?? filtered.length;
		return filtered.slice(offset, offset + limit).map(cloneToken);
	}

	public override async close(): Promise<void> {
		return;
	}

	private enforceCapacity(): void {
		if (!this.maxTokens) {
			return;
		}
		while (this.tokens.size > this.maxTokens) {
			const oldestRefresh = this.tokens.keys().next().value;
			if (!oldestRefresh) {
				return;
			}
			this.removeByRefreshToken(oldestRefresh);
		}
	}
}
