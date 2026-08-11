import { ApiModule } from '../api-module.js';

import type { ApiRequest } from '../apicore-server.js';
import type { Token, TokenPair } from '../token/types.js';

// Minimal surface an auth module must expose to plug into ApiServer.

export interface AuthProviderModule<UserRow = unknown> {
	readonly moduleType: 'auth';
	readonly namespace: string;
	issueTokens(apiReq: ApiRequest, user: UserRow, metadata?: Partial<Token> & { expires?: Date }): Promise<TokenPair>;
}

// Handy base that you can extend when wiring a real auth module. Subclasses
// must supply a namespace via the constructor and implement token issuance.

export abstract class BaseAuthModule<UserRow = unknown> extends ApiModule implements AuthProviderModule<UserRow> {
	public readonly moduleType = 'auth' as const;

	protected constructor(opts: { namespace: string }) {
		super(opts);
	}

	// Override to mint tokens for the provided user and request context
	public abstract issueTokens(
		apiReq: ApiRequest,
		user: UserRow,
		metadata?: Partial<Token> & { expires?: Date }
	): Promise<TokenPair>;
}

class NullAuthModule extends BaseAuthModule<unknown> {
	public constructor() {
		super({ namespace: '__null__' });
	}

	public override async issueTokens(
		apiReq: ApiRequest,
		user: unknown,
		metadata?: Partial<Token> & { expires?: Date }
	): Promise<TokenPair> {
		void apiReq;
		void user;
		void metadata;
		throw new Error('Auth module not configured. Inject a real auth module before issuing tokens.');
	}
}

export const nullAuthModule: AuthProviderModule<unknown> = new NullAuthModule();
