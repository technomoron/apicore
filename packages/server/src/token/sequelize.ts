import {
	CreationOptional,
	DataTypes,
	Model,
	Op,
	type InferAttributes,
	type InferCreationAttributes,
	type ModelStatic,
	type Sequelize
} from 'sequelize';

import { normalizeStringUserId } from '../auth-api/user-id.js';
import {
	decodeStringArray,
	encodeStringArray,
	integerIdType,
	tableOptions
} from '../sequelize-utils.js';

import { assertTokenLookupField, hasTokenDeleteField, TokenStore } from './base.js';

import type { Token } from './types.js';

class TokenModel
	extends Model<InferAttributes<TokenModel>, InferCreationAttributes<TokenModel>>
	implements InferAttributes<TokenModel>
{
	declare token_id: CreationOptional<number>;
	declare user_id: string;
	declare real_user_id: CreationOptional<string | null>;
	declare expires: Date;
	declare issued_at: CreationOptional<Date>;
	declare last_seen_at: CreationOptional<Date>;
	declare access: string;
	declare refresh: string;
	declare session_id: CreationOptional<string | null>;
	declare domain: CreationOptional<string>;
	declare fingerprint: CreationOptional<string>;
	declare label: CreationOptional<string>;
	declare browser: CreationOptional<string>;
	declare device: CreationOptional<string>;
	declare ip: CreationOptional<string>;
	declare os: CreationOptional<string>;
	declare client_id: CreationOptional<string | null>;
	declare scope: CreationOptional<string>;
	declare login_type: CreationOptional<string>;
	declare refresh_ttl_seconds: CreationOptional<number | null>;
	declare session_cookie: CreationOptional<boolean>;
}

type TokenModelUpdates = Partial<InferAttributes<TokenModel>>;
type UpdateField<K extends keyof Token> = {
	tokenKey: K;
	modelKey: keyof TokenModelUpdates;
	convert?: (value: NonNullable<Token[K]>) => TokenModelUpdates[keyof TokenModelUpdates];
};
type QueryField<K extends keyof Token> = {
	tokenKey: K;
	modelKey: string;
	accept?: (value: Token[K]) => boolean;
	convert?: (value: NonNullable<Token[K]>) => unknown;
};

const STRING_UPDATE_FIELDS: Array<
	UpdateField<
		keyof Pick<Token, 'label' | 'domain' | 'fingerprint' | 'browser' | 'device' | 'ip' | 'os' | 'loginType'>
	>
> = [
	{ tokenKey: 'label', modelKey: 'label', convert: (value) => value ?? '' },
	{ tokenKey: 'domain', modelKey: 'domain', convert: (value) => value ?? '' },
	{ tokenKey: 'fingerprint', modelKey: 'fingerprint', convert: (value) => value ?? '' },
	{ tokenKey: 'browser', modelKey: 'browser', convert: (value) => value ?? '' },
	{ tokenKey: 'device', modelKey: 'device', convert: (value) => value ?? '' },
	{ tokenKey: 'ip', modelKey: 'ip', convert: (value) => value ?? '' },
	{ tokenKey: 'os', modelKey: 'os', convert: (value) => value ?? '' },
	{ tokenKey: 'loginType', modelKey: 'login_type', convert: (value) => value ?? '' }
];

const TOKEN_QUERY_FIELDS: Array<
	QueryField<
		keyof Pick<
			Token,
			'refreshToken' | 'sessionId' | 'accessToken' | 'clientId' | 'domain' | 'fingerprint' | 'label'
		>
	>
> = [
	{ tokenKey: 'refreshToken', modelKey: 'refresh', accept: Boolean },
	{ tokenKey: 'sessionId', modelKey: 'session_id', accept: Boolean },
	{ tokenKey: 'accessToken', modelKey: 'access', accept: Boolean },
	{ tokenKey: 'clientId', modelKey: 'client_id', accept: Boolean },
	{ tokenKey: 'domain', modelKey: 'domain', accept: (value) => value !== undefined && value !== null },
	{ tokenKey: 'fingerprint', modelKey: 'fingerprint', accept: (value) => value !== undefined && value !== null },
	{ tokenKey: 'label', modelKey: 'label', accept: Boolean }
];

export type TokenAttributes = InferAttributes<TokenModel>;
export type TokenCreationAttributes = InferCreationAttributes<TokenModel>;

function initTokenModel(sequelize: Sequelize, options: { tablePrefix?: string } = {}): typeof TokenModel {
	TokenModel.init(
		{
			token_id: {
				type: integerIdType(sequelize),
				autoIncrement: true,
				allowNull: false,
				primaryKey: true
			},
			user_id: {
				type: DataTypes.STRING(191),
				allowNull: false
			},
			real_user_id: {
				type: DataTypes.STRING(191),
				allowNull: true,
				defaultValue: null
			},
			expires: {
				type: DataTypes.DATE,
				allowNull: false
			},
			issued_at: {
				type: DataTypes.DATE,
				allowNull: false,
				defaultValue: DataTypes.NOW
			},
			last_seen_at: {
				type: DataTypes.DATE,
				allowNull: false,
				defaultValue: DataTypes.NOW
			},
			access: {
				type: DataTypes.TEXT,
				allowNull: false
			},
			refresh: {
				type: DataTypes.TEXT,
				allowNull: false
			},
			session_id: {
				type: DataTypes.STRING(64),
				allowNull: true,
				defaultValue: null
			},
			domain: {
				type: DataTypes.STRING(64),
				allowNull: false,
				defaultValue: ''
			},
			fingerprint: {
				type: DataTypes.STRING(64),
				allowNull: false,
				defaultValue: ''
			},
			label: {
				type: DataTypes.STRING(128),
				allowNull: false,
				defaultValue: ''
			},
			browser: {
				type: DataTypes.STRING(64),
				allowNull: false,
				defaultValue: ''
			},
			device: {
				type: DataTypes.STRING(64),
				allowNull: false,
				defaultValue: ''
			},
			ip: {
				type: DataTypes.STRING(45),
				allowNull: false,
				defaultValue: ''
			},
			os: {
				type: DataTypes.STRING(64),
				allowNull: false,
				defaultValue: ''
			},
			login_type: {
				type: DataTypes.STRING(64),
				allowNull: false,
				defaultValue: ''
			},
			refresh_ttl_seconds: {
				type: DataTypes.INTEGER,
				allowNull: true,
				defaultValue: null
			},
			session_cookie: {
				type: DataTypes.BOOLEAN,
				allowNull: false,
				defaultValue: false
			},
			client_id: {
				type: DataTypes.STRING(128),
				allowNull: true,
				defaultValue: null
			},
			scope: {
				type: DataTypes.TEXT,
				allowNull: false,
				defaultValue: '[]'
			}
		},
		{
			...tableOptions(sequelize, 'jwttokens', options.tablePrefix, {
				timestamps: false
			})
		}
	);

	return TokenModel;
}

export interface SequelizeTokenStoreOptions {
	sequelize: Sequelize;
	tablePrefix?: string;
	tokenModel?: ModelStatic<TokenModel>;
	tokenModelFactory?: (sequelize: Sequelize, options?: { tablePrefix?: string }) => ModelStatic<TokenModel>;
}

export class SequelizeTokenStore extends TokenStore {
	public readonly Tokens: ModelStatic<TokenModel>;
	private sessionIdColumnReady = false;
	private sessionIdColumnReadyPromise?: Promise<void>;

	constructor(options: SequelizeTokenStoreOptions) {
		super();
		if (!options?.sequelize) {
			throw new Error('SequelizeTokenStore requires an initialised Sequelize instance');
		}
		this.Tokens =
			options.tokenModel ??
			(options.tokenModelFactory ?? initTokenModel)(options.sequelize, {
				tablePrefix: options.tablePrefix
			});
	}

	public override async save(record: Token): Promise<void> {
		await this.ensureSessionIdColumn();
		const normalized = this.normalizeToken(record);
		const resolvedUserId = this.normalizeUserId(normalized.userId);
		const resolvedRealUserId = this.resolveRealUserId(normalized.ruid);
		const domain = normalized.domain;
		const fingerprint = normalized.fingerprint;
		const browser = normalized.browser;
		const device = normalized.device;
		const ip = normalized.ip;
		const os = normalized.os;
		const label = normalized.label;
		const loginType = normalized.loginType ?? '';
		const refreshTtlSeconds =
			typeof normalized.refreshTtlSeconds === 'number' && normalized.refreshTtlSeconds > 0
				? Math.floor(normalized.refreshTtlSeconds)
				: null;
		const issuedAt = normalized.issuedAt ?? new Date();
		const lastSeenAt = normalized.lastSeenAt ?? issuedAt;
		const sessionCookie = normalized.sessionCookie ?? false;

		const removalWhere: Record<string, unknown> = {
			user_id: resolvedUserId
		};
		if (record.domain !== undefined) {
			removalWhere.domain = domain;
		}
		if (record.fingerprint !== undefined) {
			removalWhere.fingerprint = fingerprint;
		}
		if (normalized.clientId) {
			removalWhere.client_id = normalized.clientId;
		}

		const sequelize = this.Tokens.sequelize;
		if (!sequelize) {
			throw new Error('Token model is not bound to a Sequelize instance');
		}

		await sequelize.transaction(async (transaction) => {
			await this.Tokens.destroy({ where: removalWhere, transaction });
			// Remove stale token collisions before insert. Only include non-empty token values
			// to prevent matching unrelated rows.
			const collisionConditions: Record<string, string>[] = [];
			if (normalized.accessToken) {
				collisionConditions.push({ access: normalized.accessToken });
			}
			if (normalized.refreshToken) {
				collisionConditions.push({ refresh: normalized.refreshToken });
			}
			if (normalized.sessionId) {
				collisionConditions.push({ session_id: normalized.sessionId });
			}
			if (collisionConditions.length > 0) {
				await this.Tokens.destroy({
					where: { [Op.or]: collisionConditions },
					transaction
				});
			}

			await this.Tokens.create(
				{
					user_id: resolvedUserId,
					real_user_id: resolvedRealUserId,
					access: normalized.accessToken ?? '',
					refresh: normalized.refreshToken,
					session_id: normalized.sessionId,
					expires: normalized.expires,
					issued_at: issuedAt,
					last_seen_at: lastSeenAt,
					domain,
					fingerprint,
					label,
					browser,
					device,
					ip,
					os,
					client_id: normalized.clientId ?? null,
					scope: this.encodeScope(normalized.scope),
					login_type: loginType,
					refresh_ttl_seconds: refreshTtlSeconds,
					session_cookie: sessionCookie
				} as TokenCreationAttributes,
				{ transaction }
			);
		});
	}

	private async ensureSessionIdColumn(): Promise<void> {
		if (this.sessionIdColumnReady) {
			return;
		}
		this.sessionIdColumnReadyPromise ??= this.ensureSessionIdColumnOnce();
		await this.sessionIdColumnReadyPromise;
	}

	private async ensureSessionIdColumnOnce(): Promise<void> {
		if (!this.Tokens.rawAttributes.session_id) {
			this.sessionIdColumnReady = true;
			return;
		}
		const sequelize = this.Tokens.sequelize;
		if (!sequelize) {
			this.sessionIdColumnReady = true;
			return;
		}
		const tableName = this.Tokens.getTableName();
		const columns = await sequelize.getQueryInterface().describeTable(tableName);
		if (columns.session_id) {
			this.sessionIdColumnReady = true;
			return;
		}
		await sequelize.getQueryInterface().addColumn(tableName, 'session_id', {
			type: DataTypes.STRING(64),
			allowNull: true,
			defaultValue: null
		});
		this.sessionIdColumnReady = true;
	}

	public override async get(query: Partial<Token>, opts?: { includeExpired?: boolean }): Promise<Token | null> {
		assertTokenLookupField(query);
		const model = await this.Tokens.findOne({ where: this.tokenWhere(query, opts) });
		return model ? this.toTokenRecord(model) : null;
	}

	public override async delete(query: Partial<Token>): Promise<number> {
		if (!hasTokenDeleteField(query)) {
			return 0;
		}

		return this.Tokens.destroy({ where: this.tokenWhere(query, { includeExpired: true }) });
	}

	public override async update(params: Partial<Token> & { refreshToken: string }): Promise<boolean> {
		const updates = this.tokenUpdates(params);
		if (Object.keys(updates).length === 0) {
			return false;
		}
		const sequelize = this.Tokens.sequelize;
		if (!sequelize) {
			throw new Error('Token model is not bound to a Sequelize instance');
		}
		return sequelize.transaction(async (transaction) => {
			const [updated] = await this.Tokens.update(updates, {
				where: this.tokenUpdateWhere(params),
				transaction
			});
			return updated > 0;
		});
	}

	public override async list(
		userId: string | number,
		opts: {
			limit?: number;
			offset?: number;
			includeExpired?: boolean;
		} = {}
	): Promise<Token[]> {
		const where: Record<string, unknown> = {
			user_id: this.normalizeUserId(userId)
		};
		if (!(opts.includeExpired ?? false)) {
			where.expires = { [Op.gt]: new Date() };
		}

		const models = await this.Tokens.findAll({
			where,
			order: [['issued_at', 'DESC']],
			limit: opts.limit,
			offset: opts.offset
		});
		return models.map((model) => this.toTokenRecord(model));
	}

	public override async close(): Promise<void> {
		return;
	}

	private normalizeUserId(identifier: string | number): string {
		return normalizeStringUserId(identifier);
	}

	private tokenUpdateWhere(params: Partial<Token> & { refreshToken: string }): Record<string, unknown> {
		const where: Record<string, unknown> = { refresh: params.refreshToken };
		if (params.clientId) {
			where.client_id = params.clientId;
		}
		return where;
	}

	private tokenUpdates(params: Partial<Token>): TokenModelUpdates {
		const updates: TokenModelUpdates = {};
		this.assignPresent(updates, 'access', params.accessToken);
		this.assignPresent(updates, 'session_id', params.sessionId);
		this.assignPresent(updates, 'expires', params.expires);
		this.assignPresent(updates, 'issued_at', params.issuedAt);
		this.assignPresent(updates, 'last_seen_at', params.lastSeenAt);
		if (params.scope !== undefined) {
			updates.scope = this.encodeScope(params.scope);
		}
		for (const field of STRING_UPDATE_FIELDS) {
			this.assignTokenField(updates, params, field);
		}
		if (params.refreshTtlSeconds !== undefined) {
			updates.refresh_ttl_seconds = this.normalizeRefreshTtlSeconds(params.refreshTtlSeconds);
		}
		if (params.sessionCookie !== undefined) {
			updates.session_cookie = params.sessionCookie;
		}
		return updates;
	}

	private assignPresent<K extends keyof TokenModelUpdates>(
		updates: TokenModelUpdates,
		modelKey: K,
		value: TokenModelUpdates[K] | null | undefined
	): void {
		if (value !== undefined && value !== null) {
			updates[modelKey] = value;
		}
	}

	private assignTokenField<K extends keyof Token>(
		updates: TokenModelUpdates,
		params: Partial<Token>,
		field: UpdateField<K>
	): void {
		const value = params[field.tokenKey];
		if (value !== undefined) {
			(updates as Record<string, unknown>)[String(field.modelKey)] = field.convert
				? field.convert(value as NonNullable<Token[K]>)
				: value;
		}
	}

	private normalizeRefreshTtlSeconds(value: Token['refreshTtlSeconds']): number | null {
		return typeof value === 'number' && value > 0 ? Math.floor(value) : null;
	}

	private tokenWhere(query: Partial<Token>, opts?: { includeExpired?: boolean }): Record<string, unknown> {
		const where: Record<string, unknown> = {};
		for (const field of TOKEN_QUERY_FIELDS) {
			this.assignQueryField(where, query, field);
		}
		if (query.userId !== undefined) {
			where.user_id = this.normalizeUserId(query.userId);
		}
		if (!(opts?.includeExpired ?? false)) {
			where.expires = { [Op.gt]: new Date() };
		}
		return where;
	}

	private assignQueryField<K extends keyof Token>(
		where: Record<string, unknown>,
		query: Partial<Token>,
		field: QueryField<K>
	): void {
		const value = query[field.tokenKey];
		if (value !== undefined && (field.accept?.(value) ?? true)) {
			where[field.modelKey] = field.convert ? field.convert(value as NonNullable<Token[K]>) : value;
		}
	}

	private resolveRealUserId(ruid: string | number | undefined): string | null {
		if (ruid === undefined || ruid === null) {
			return null;
		}
		const value = String(ruid);
		if (value.length === 0 || value === '0') {
			return null;
		}
		return value;
	}

	private encodeScope(scope?: string | string[]): string {
		if (!scope || (Array.isArray(scope) && scope.length === 0)) {
			return '[]';
		}
		if (Array.isArray(scope)) {
			return encodeStringArray(scope);
		}
		return encodeStringArray(scope.split(/\s+/).filter((entry) => entry.length > 0));
	}

	private toTokenRecord(model: TokenModel): Token {
		const scope = decodeStringArray(model.scope);
		const normalized = this.normalizeToken({
			userId: model.user_id,
			refreshToken: model.refresh,
			accessToken: model.access,
			sessionId: model.session_id ?? undefined,
			expires: model.expires,
			issuedAt: model.issued_at,
			lastSeenAt: model.last_seen_at,
			domain: model.domain,
			fingerprint: model.fingerprint,
			label: model.label,
			browser: model.browser,
			device: model.device,
			ip: model.ip,
			os: model.os,
			clientId: model.client_id ?? undefined,
			scope,
			loginType: model.login_type || undefined,
			refreshTtlSeconds: model.refresh_ttl_seconds ?? undefined,
			ruid: model.real_user_id ?? undefined,
			sessionCookie: model.session_cookie
		});
		if (!model.session_id) {
			delete normalized.sessionId;
		}
		return {
			...normalized,
			scope: normalized.scope ? [...normalized.scope] : undefined
		};
	}
}
