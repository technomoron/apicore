import { normalizePasskeyConfig } from '../passkey/config.js';

import { CompositeAuthAdapter } from './compat-auth-storage.js';
import { createPasskeyUserResolver } from './passkey-user.js';

import type { AuthIdentifier } from './types.js';
import type { OAuthStore } from '../oauth/base.js';
import type { PasskeyStore } from '../passkey/base.js';
import type { PasskeyServiceConfig, PasskeyUserDescriptor } from '../passkey/types.js';
import type { TokenStore } from '../token/base.js';
import type { UserStore } from '../user/base.js';

interface AuthStoreAdapterOptions<UserAttributes, PublicUserShape, Store extends PasskeyStore> {
	userStore: UserStore<UserAttributes, PublicUserShape>;
	tokenStore: TokenStore;
	oauthStore: OAuthStore;
	passkeys?: false | Partial<PasskeyServiceConfig>;
	passkeyUserMapper?: (user: UserAttributes) => PasskeyUserDescriptor;
	toPasskeyUser: (user: UserAttributes) => PasskeyUserDescriptor;
	createPasskeyStore: (
		resolveUser: (lookup: { userId?: AuthIdentifier; login?: string }) => Promise<PasskeyUserDescriptor | null>
	) => Store;
	canImpersonate?: (params: {
		realUserId: AuthIdentifier;
		effectiveUserId: AuthIdentifier;
	}) => boolean | Promise<boolean>;
}

export function createAuthStoreAdapter<UserAttributes, PublicUserShape, Store extends PasskeyStore>(
	options: AuthStoreAdapterOptions<UserAttributes, PublicUserShape, Store>
): { adapter: CompositeAuthAdapter<UserAttributes, PublicUserShape>; passkeyStore?: Store } {
	const passkeyConfig = options.passkeys === false ? undefined : normalizePasskeyConfig(options.passkeys ?? {});
	const passkeyStore = passkeyConfig
		? options.createPasskeyStore(
				createPasskeyUserResolver({
					findUser: (identifier) => options.userStore.findUser(identifier),
					mapper: options.passkeyUserMapper,
					toDescriptor: options.toPasskeyUser
				})
			)
		: undefined;
	const adapter = new CompositeAuthAdapter<UserAttributes, PublicUserShape>({
		userStore: options.userStore,
		tokenStore: options.tokenStore,
		passkeys: passkeyStore && passkeyConfig ? { store: passkeyStore, config: passkeyConfig } : undefined,
		oauthStore: options.oauthStore,
		canImpersonate: options.canImpersonate
	});
	return { adapter, passkeyStore };
}
