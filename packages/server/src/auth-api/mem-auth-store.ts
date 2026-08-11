import { MemoryOAuthStore } from '../oauth/memory.js';
import { MemoryPasskeyStore } from '../passkey/memory.js';
import { TokenStore } from '../token/base.js';
import { MemoryTokenStore } from '../token/memory.js';
import { MemoryUserStore } from '../user/memory.js';

import { createAuthStoreAdapter } from './auth-store-adapter.js';
import { AuthStoreDelegate } from './auth-store-delegate.js';

import type { AuthIdentifier } from './types.js';
import type { MemoryOAuthStoreOptions } from '../oauth/memory.js';
import type { MemoryPasskeyStoreOptions } from '../passkey/memory.js';
import type { PasskeyServiceConfig, PasskeyUserDescriptor } from '../passkey/types.js';
import type { MemoryUserAttributes, MemoryPublicUser, MemoryUserStoreOptions } from '../user/memory.js';

interface PasskeyOptions extends Partial<PasskeyServiceConfig> {
	enabled?: boolean;
}

export interface MemAuthStoreParams<
	UserAttributes extends MemoryUserAttributes = MemoryUserAttributes,
	PublicUserShape extends MemoryPublicUser<UserAttributes> = MemoryPublicUser<UserAttributes>
>
	extends
		Omit<MemoryUserStoreOptions<UserAttributes, PublicUserShape>, 'hasher'>,
		MemoryOAuthStoreOptions,
		Partial<MemoryPasskeyStoreOptions> {
	bcryptRounds?: number;
	passwordPepper?: string;
	publicUserMapper?: (user: UserAttributes) => PublicUserShape;
	passkeyUserMapper?: (user: UserAttributes) => PasskeyUserDescriptor;
	passkeys?: false | PasskeyOptions;
	canImpersonate?: (params: {
		realUserId: AuthIdentifier;
		effectiveUserId: AuthIdentifier;
	}) => boolean | Promise<boolean>;
	tokenStore?: TokenStore;
}

export class MemAuthStore<
	UserAttributes extends MemoryUserAttributes = MemoryUserAttributes,
	PublicUserShape extends MemoryPublicUser<UserAttributes> = MemoryPublicUser<UserAttributes>
> extends AuthStoreDelegate<UserAttributes, PublicUserShape> {
	public readonly userStore: MemoryUserStore<UserAttributes, PublicUserShape>;
	public readonly tokenStore: TokenStore;
	public readonly passkeyStore?: MemoryPasskeyStore;
	public readonly oauthStore: MemoryOAuthStore;

	constructor(params: MemAuthStoreParams<UserAttributes, PublicUserShape> = {}) {
		super();
		this.userStore = new MemoryUserStore({
			toPublic: params.publicUserMapper ?? params.toPublic,
			userIdFactory: params.userIdFactory,
			startingUserId: params.startingUserId,
			bcryptRounds: params.bcryptRounds,
			bcryptPepper: params.passwordPepper
		});
		this.tokenStore = params.tokenStore ?? new MemoryTokenStore();
		this.oauthStore = new MemoryOAuthStore({
			bcryptRounds: params.bcryptRounds
		});

		const configured = createAuthStoreAdapter({
			userStore: this.userStore,
			tokenStore: this.tokenStore,
			oauthStore: this.oauthStore,
			passkeys: params.passkeys,
			passkeyUserMapper: params.passkeyUserMapper,
			toPasskeyUser: (user: UserAttributes): PasskeyUserDescriptor => ({
				id: user.user_id,
				login: user.login,
				displayName: user.login
			}),
			createPasskeyStore: (resolveUser) => new MemoryPasskeyStore({ resolveUser }),
			canImpersonate: params.canImpersonate
		});
		this.passkeyStore = configured.passkeyStore;
		this.adapter = configured.adapter;
	}

	public async initialise(): Promise<void> {
		return;
	}

	public async close(): Promise<void> {
		return;
	}
}
