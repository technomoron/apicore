import ApiServer, {
	ApiError,
	ApiModule,
	type ApiAuthClass,
	type ApiKey,
	type ApiRequest,
	type ApiRoute,
	type ApiTokenData
} from '../../src/apicore-server';
import { BaseAuthAdapter } from '../../src/auth-api/storage.js';

import type { AuthIdentifier } from '../../src/auth-api/types.js';
import type { Token } from '../../src/token/types.js';

export interface TestUser {
	id: string;
	email: string;
	role: ApiAuthClass;
	password: string;
}

export type StoreTokenParams = Token;
export type GetTokenParams = Partial<Omit<Token, 'userId' | 'ruid'>> & {
	userId?: string | number;
	ruid?: string | number;
};
export type UpdateTokenParams = Parameters<ApiServer['updateToken']>[0];
export type DeleteTokenParams = Partial<Omit<Token, 'userId' | 'ruid'>> & {
	userId?: string | number;
	ruid?: string | number;
};

class TestAuthStorage extends BaseAuthAdapter<TestUser, Omit<TestUser, 'password'>> {
	constructor(private readonly server: TestServer) {
		super();
	}

	public override async getUser(identifier: AuthIdentifier): Promise<TestUser | null> {
		return this.server.users.get(String(identifier)) ?? null;
	}

	public override getUserPasswordHash(user: TestUser): string {
		return user.password;
	}

	public override getUserId(user: TestUser): AuthIdentifier {
		return user.id;
	}

	public override filterUser(user: TestUser): Omit<TestUser, 'password'> {
		const { password: _password, ...safe } = user;
		void _password;
		return safe;
	}

	public override async verifyPassword(password: string, hash: string): Promise<boolean> {
		return password === hash;
	}

	public override async storeToken(params: StoreTokenParams): Promise<void> {
		this.server.storedTokens.push(params);
		this.server.tokens.set(params.refreshToken, params);
	}

	public override async getToken(query: GetTokenParams, _opts?: { includeExpired?: boolean }): Promise<Token | null> {
		void _opts;
		if (query.refreshToken) {
			return this.server.tokens.get(query.refreshToken) ?? null;
		}
		if (query.sessionId) {
			for (const token of this.server.tokens.values()) {
				if (token.sessionId === query.sessionId) {
					return token;
				}
			}
		}
		if (query.accessToken) {
			for (const token of this.server.tokens.values()) {
				if (token.accessToken === query.accessToken) {
					return token;
				}
			}
		}
		if (query.userId !== undefined) {
			for (const token of this.server.tokens.values()) {
				if (token.userId === query.userId) {
					return token;
				}
			}
		}
		return null;
	}

	public override async updateToken(updates: Partial<Token> & { refreshToken: string }): Promise<boolean> {
		const existing = this.server.tokens.get(updates.refreshToken);
		if (!existing) {
			return false;
		}
		const next: Token = {
			...existing,
			...(updates.accessToken ? { accessToken: updates.accessToken } : {}),
			...(Object.prototype.hasOwnProperty.call(updates, 'expires') ? { expires: updates.expires } : {}),
			...(updates.clientId ? { clientId: updates.clientId } : {}),
			...(updates.scope ? { scope: updates.scope } : {})
		};
		this.server.tokens.set(updates.refreshToken, next);
		return true;
	}

	public override async deleteToken(query: DeleteTokenParams): Promise<number> {
		let removed = 0;
		if (query.refreshToken && this.server.tokens.delete(query.refreshToken)) {
			removed += 1;
		}
		if (query.accessToken) {
			for (const [key, token] of [...this.server.tokens.entries()]) {
				if (token.accessToken === query.accessToken) {
					this.server.tokens.delete(key);
					removed += 1;
				}
			}
		}
		if (query.sessionId) {
			for (const [key, token] of [...this.server.tokens.entries()]) {
				if (token.sessionId === query.sessionId) {
					this.server.tokens.delete(key);
					removed += 1;
				}
			}
		}
		if (query.userId !== undefined) {
			for (const [key, token] of [...this.server.tokens.entries()]) {
				if (token.userId === query.userId) {
					this.server.tokens.delete(key);
					removed += 1;
				}
			}
		}
		return removed;
	}

	public async listTokens(
		userId: string | number,
		opts: {
			limit?: number;
			offset?: number;
			includeExpired?: boolean;
		} = {}
	): Promise<Token[]> {
		const matching = [...this.server.tokens.values()].filter((token) => token.userId === String(userId));
		const offset = opts.offset ?? 0;
		const limit = opts.limit ?? matching.length;
		return matching.slice(offset, offset + limit);
	}
}

export class TestServer extends ApiServer {
	public readonly users = new Map<string, TestUser>();
	public readonly apiKeys = new Map<string, ApiKey>();
	public readonly storedTokens: StoreTokenParams[] = [];
	public readonly tokens = new Map<string, Token>();
	public readonly storage: TestAuthStorage;

	constructor(overrides: Partial<ConstructorParameters<typeof ApiServer>[0]> = {}) {
		super({
			accessSecret: 'access-secret',
			refreshSecret: 'refresh-secret',
			...overrides
		});
		this.storage = new TestAuthStorage(this);
		this.authStorage(this.storage);
	}

	public override async getApiKey(token: string): Promise<ApiKey | null> {
		return this.apiKeys.get(token) ?? super.getApiKey(token);
	}

	public override async authenticateUser(params: unknown): Promise<boolean> {
		return params !== null;
	}

	public override async authorize(apiReq: ApiRequest, requiredClass: ApiAuthClass): Promise<void> {
		if (requiredClass === 'admin' && apiReq.tokenData?.role !== 'admin') {
			throw new ApiError({ code: 403, message: 'Forbidden' });
		}
	}
}

export class ExampleModule extends ApiModule<TestServer> {
	constructor() {
		super({ namespace: '/example' });
	}

	public override defineRoutes(): ApiRoute[] {
		return [
			{
				method: 'get',
				path: '/public',
				auth: { type: 'none', req: 'any' },
				handler: async () => [200, { ok: true }]
			},
			{
				method: 'get',
				path: '/optional',
				auth: { type: 'maybe', req: 'any' },
				handler: async ({ tokenData }) => [200, { authenticated: Boolean(tokenData) }]
			},
			{
				method: 'get',
				path: '/secure',
				auth: { type: 'yes', req: 'any' },
				handler: async ({ tokenData }) => [200, { uid: tokenData?.uid }]
			},
			{
				method: 'get',
				path: '/admin',
				auth: { type: 'yes', req: 'admin' },
				handler: async ({ tokenData }) => [200, { role: tokenData?.role }]
			},
			{
				method: 'get',
				path: '/strict',
				auth: { type: 'strict', req: 'any' },
				handler: async ({ tokenData }) => [200, { uid: tokenData?.uid }]
			},
			{
				method: 'get',
				path: '/apikey',
				auth: { type: 'apikey', req: 'any' },
				handler: async ({ tokenData, token }) => [200, { uid: tokenData?.uid, token }]
			},
			{
				method: 'get',
				path: '/whoami',
				auth: { type: 'yes', req: 'any' },
				handler: async (apiReq) => [
					200,
					{
						uid: apiReq.tokenData?.uid,
						realUid: apiReq.getRealUid(),
						isImpersonating: apiReq.isImpersonating(),
						authMethod: apiReq.authMethod
					}
				]
			},
			{
				method: 'get',
				path: '/boom',
				auth: { type: 'none', req: 'any' },
				handler: async () => {
					throw new ApiError({
						code: 418,
						message: 'Teapot',
						data: { reason: 'test' },
						errors: { field: 'bad' }
					});
				}
			},
			{
				method: 'get',
				path: '/crash',
				auth: { type: 'none', req: 'any' },
				handler: async () => {
					throw new Error('Unexpected failure');
				}
			},
			{
				method: 'get',
				path: '/invalid-result',
				auth: { type: 'none', req: 'any' },
				handler: async () => undefined as unknown as [number]
			},
			{
				method: 'get',
				path: '/bad-status',
				auth: { type: 'none', req: 'any' },
				handler: async () => ['oops'] as unknown as [number]
			},
			{
				method: 'get',
				path: '/handler-404',
				auth: { type: 'none', req: 'any' },
				handler: async () => [404, null, 'Handler-level missing']
			},
			{
				method: 'patch',
				path: '/patchable',
				auth: { type: 'none', req: 'any' },
				handler: async ({ req }) => [200, { patched: true, body: req.body ?? {} }]
			},
			{
				// Returns credential-shaped fields so debug response redaction can be asserted.
				method: 'post',
				path: '/echo-secrets',
				auth: { type: 'none', req: 'any' },
				handler: async () => [
					200,
					{
						accessToken: 'header.payload.signature',
						refreshToken: 'short-refresh-abc123',
						apiKey: 'sk_live_short_42',
						userId: 'user-1'
					}
				]
			}
		];
	}
}

export const createServer = (overrides: Partial<ConstructorParameters<typeof ApiServer>[0]> = {}): TestServer => {
	const server = new TestServer({
		accessSecret: 'test-access-secret',
		refreshSecret: 'test-refresh-secret',
		origins: ['http://allowed.test'],
		...overrides
	});

	server.users.set('user-1', {
		id: 'user-1',
		email: 'user@test.dev',
		role: 'any',
		password: 'secret'
	});
	server.users.set('admin-1', {
		id: 'admin-1',
		email: 'admin@test.dev',
		role: 'admin',
		password: 'secret'
	});

	server.apiKeys.set('key-123', { uid: 'api-user' });
	server.apiKeys.set('key-impersonate', { uid: 'api-user', euid: 'user-1' });

	const module = new ExampleModule();
	server.api(module);
	return server;
};

export type CreateTokenPayload = ApiTokenData & Record<string, unknown>;

export const signToken = (server: TestServer, payload: CreateTokenPayload, expiresInSeconds = 60): string => {
	const result = server.jwtSign(payload, server.config.accessSecret, expiresInSeconds);
	if (!result.success || !result.token) {
		throw new Error(result.error ?? 'Failed to sign token');
	}
	return result.token;
};
