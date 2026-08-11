import { Sequelize, type SyncOptions } from 'sequelize';

import { SequelizeOAuthStore, type SequelizeOAuthStoreOptions } from '../oauth/sequelize.js';
import { SequelizePasskeyStore } from '../passkey/sequelize.js';
import { normalizeTablePrefix } from '../sequelize-utils.js';
import { SequelizeTokenStore, type SequelizeTokenStoreOptions } from '../token/sequelize.js';
import {
	SequelizeUserStore,
	type AuthUserAttributes,
	GenericUserModel,
	GenericUserModelStatic
} from '../user/sequelize.js';

import { createAuthStoreAdapter } from './auth-store-adapter.js';
import { AuthStoreDelegate } from './auth-store-delegate.js';

import type { AuthIdentifier } from './types.js';
import type { PasskeyServiceConfig, PasskeyUserDescriptor } from '../passkey/types.js';
import type { TokenStore } from '../token/base.js';

interface PasskeyOptions extends Partial<PasskeyServiceConfig> {
	enabled?: boolean;
}

export interface SqlAuthStoreTablePrefixes {
	user?: string;
	token?: string;
	passkey?: string;
	oauth?: string;
}

export interface SqlAuthStoreParams<
	UserAttributes extends AuthUserAttributes = AuthUserAttributes,
	PublicUserShape extends Omit<UserAttributes, 'password'> = Omit<UserAttributes, 'password'>
> {
	sequelize: Sequelize;
	syncOptions?: SyncOptions;
	bcryptRounds?: number;
	passwordPepper?: string;
	tablePrefix?: string;
	tablePrefixes?: SqlAuthStoreTablePrefixes;
	userModel?: GenericUserModelStatic;
	userModelFactory?: (sequelize: Sequelize, options?: { tablePrefix?: string }) => GenericUserModelStatic;
	userRecordMapper?: (model: GenericUserModel) => UserAttributes;
	publicUserMapper?: (user: UserAttributes) => PublicUserShape;
	passkeyUserMapper?: (user: UserAttributes) => PasskeyUserDescriptor;
	passkeys?: false | PasskeyOptions;
	canImpersonate?: (params: {
		realUserId: AuthIdentifier;
		effectiveUserId: AuthIdentifier;
	}) => boolean | Promise<boolean>;
	tokenStore?: TokenStore;
	tokenStoreOptions?: Omit<SequelizeTokenStoreOptions, 'sequelize'>;
	oauthStoreOptions?: Omit<SequelizeOAuthStoreOptions, 'sequelize'>;
}

function resolveTablePrefix(...prefixes: Array<string | undefined>): string | undefined {
	for (const prefix of prefixes) {
		const normalized = normalizeTablePrefix(prefix);
		if (normalized) {
			return normalized;
		}
	}
	return undefined;
}

export class SqlAuthStore<
	UserAttributes extends AuthUserAttributes = AuthUserAttributes,
	PublicUserShape extends Omit<UserAttributes, 'password'> = Omit<UserAttributes, 'password'>
> extends AuthStoreDelegate<UserAttributes, PublicUserShape> {
	public readonly userStore: SequelizeUserStore<UserAttributes, PublicUserShape>;
	public readonly tokenStore: TokenStore;
	public readonly passkeyStore?: SequelizePasskeyStore;
	public readonly oauthStore: SequelizeOAuthStore;
	private readonly sequelize: Sequelize;
	private closed = false;
	private readonly syncOptions?: SyncOptions;

	constructor(params: SqlAuthStoreParams<UserAttributes, PublicUserShape>) {
		super();
		if (!params?.sequelize) {
			throw new Error('SqlAuthStore requires an initialised Sequelize instance');
		}
		this.sequelize = params.sequelize;
		this.syncOptions = params.syncOptions;
		const moduleTablePrefixes = params.tablePrefixes ?? {};
		const userTablePrefix = resolveTablePrefix(moduleTablePrefixes.user, params.tablePrefix);
		this.userStore = new SequelizeUserStore<UserAttributes, PublicUserShape>({
			sequelize: this.sequelize,
			userModel: params.userModel,
			userModelFactory: params.userModelFactory,
			recordMapper: params.userRecordMapper,
			toPublic: params.publicUserMapper,
			bcryptRounds: params.bcryptRounds,
			bcryptPepper: params.passwordPepper,
			tablePrefix: userTablePrefix
		});
		const tokenTablePrefix = resolveTablePrefix(
			params.tokenStoreOptions?.tablePrefix,
			moduleTablePrefixes.token,
			params.tablePrefix
		);
		this.tokenStore =
			params.tokenStore ??
			new SequelizeTokenStore({
				sequelize: this.sequelize,
				...params.tokenStoreOptions,
				tablePrefix: tokenTablePrefix
			});
		const oauthTablePrefix = resolveTablePrefix(
			params.oauthStoreOptions?.tablePrefix,
			moduleTablePrefixes.oauth,
			params.tablePrefix
		);
		this.oauthStore = new SequelizeOAuthStore({
			sequelize: this.sequelize,
			...params.oauthStoreOptions,
			tablePrefix: oauthTablePrefix,
			bcryptRounds: params.bcryptRounds
		});

		const passkeyTablePrefix = resolveTablePrefix(moduleTablePrefixes.passkey, params.tablePrefix);
		const configured = createAuthStoreAdapter({
			userStore: this.userStore,
			tokenStore: this.tokenStore,
			oauthStore: this.oauthStore,
			passkeys: params.passkeys,
			passkeyUserMapper: params.passkeyUserMapper,
			toPasskeyUser: (user: UserAttributes): PasskeyUserDescriptor => {
				const userId = this.userStore.getUserId(user);
				return {
					id: (userId ?? user['user_id']) as AuthIdentifier,
					login: user.login ?? String(userId),
					displayName: user.login ?? String(userId)
				};
			},
			createPasskeyStore: (resolveUser) =>
				new SequelizePasskeyStore({
					sequelize: this.sequelize,
					resolveUser,
					tablePrefix: passkeyTablePrefix
				}),
			canImpersonate: params.canImpersonate
		});
		this.passkeyStore = configured.passkeyStore;
		this.adapter = configured.adapter;
	}

	public async initialise(withSync: boolean = false): Promise<void> {
		await this.sequelize.authenticate();
		if (withSync) {
			await this.sequelize.sync(this.syncOptions);
		}
	}

	public async close(): Promise<void> {
		if (this.closed) {
			return;
		}
		this.closed = true;
		try {
			await this.sequelize.close();
		} catch (error) {
			const message = (error as Error | undefined)?.message ?? '';
			if (!/already.*closed|pool.*end|already.*disconnected/i.test(message)) {
				throw error;
			}
		} finally {
			// Prevent double-close errors when the same Sequelize instance is shared with other code.
			this.sequelize.close = async () => {};
		}
	}
}
