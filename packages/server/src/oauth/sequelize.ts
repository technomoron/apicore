import bcrypt from 'bcryptjs';
import { Transaction } from 'sequelize';

import { normalizeNumericUserId } from '../auth-api/user-id.js';
import { decodeStringArray, encodeStringArray } from '../sequelize-utils.js';

import { OAuthStore, type AuthCode, type OAuthClient } from './base.js';
import {
	OAuthClientModel,
	OAuthCodeModel,
	initOAuthClientModel,
	initOAuthCodeModel,
	type OAuthClientCreationAttributes,
	type OAuthCodeCreationAttributes
} from './models.js';

export interface SequelizeOAuthStoreOptions {
	sequelize: import('sequelize').Sequelize;
	tablePrefix?: string;
	clientModel?: typeof OAuthClientModel;
	codeModel?: typeof OAuthCodeModel;
	clientModelFactory?: (
		sequelize: import('sequelize').Sequelize,
		options?: { tablePrefix?: string }
	) => typeof OAuthClientModel;
	codeModelFactory?: (
		sequelize: import('sequelize').Sequelize,
		options?: { tablePrefix?: string }
	) => typeof OAuthCodeModel;
	bcryptRounds?: number;
}

export {
	OAuthClientModel,
	OAuthCodeModel,
	initOAuthClientModel,
	initOAuthCodeModel,
	type OAuthClientAttributes,
	type OAuthClientCreationAttributes,
	type OAuthCodeAttributes,
	type OAuthCodeCreationAttributes
} from './models.js';

function serializeMetadata(metadata?: Record<string, unknown>): string | null {
	if (!metadata) {
		return null;
	}
	return JSON.stringify(metadata);
}

function parseMetadata(raw: string | null | undefined): Record<string, unknown> | undefined {
	if (!raw) {
		return undefined;
	}
	try {
		const parsed = JSON.parse(raw);
		if (parsed && typeof parsed === 'object') {
			return parsed as Record<string, unknown>;
		}
	} catch {
		// ignore
	}
	return undefined;
}

export class SequelizeOAuthStore extends OAuthStore {
	private readonly clients: typeof OAuthClientModel;
	private readonly codes: typeof OAuthCodeModel;
	private readonly bcryptRounds: number;

	constructor(options: SequelizeOAuthStoreOptions) {
		super();
		if (!options?.sequelize) {
			throw new Error('SequelizeOAuthStore requires an initialised Sequelize instance');
		}
		this.clients =
			options.clientModel ??
			(options.clientModelFactory ?? initOAuthClientModel)(options.sequelize, {
				tablePrefix: options.tablePrefix
			});
		this.codes =
			options.codeModel ??
			(options.codeModelFactory ?? initOAuthCodeModel)(options.sequelize, {
				tablePrefix: options.tablePrefix
			});
		this.bcryptRounds = options.bcryptRounds ?? 12;
	}

	public override async getClient(clientId: string): Promise<OAuthClient | null> {
		const model = await this.clients.findByPk(clientId);
		return model ? this.toOAuthClient(model) : null;
	}

	public override async createClient(input: OAuthClient): Promise<OAuthClient> {
		const existing = await this.clients.findByPk(input.clientId);
		const hashedSecret =
			input.clientSecret !== undefined && input.clientSecret !== null
				? await bcrypt.hash(input.clientSecret, this.bcryptRounds)
				: (existing?.client_secret ?? '');
		const redirectUris = input.redirectUris ?? (existing ? decodeStringArray(existing.redirect_uris) : undefined);
		const scope = input.scope ?? (existing ? decodeStringArray(existing.scope) : undefined);
		const metadata = input.metadata ?? (existing ? parseMetadata(existing.metadata) : undefined);
		await this.clients.upsert({
			client_id: input.clientId,
			client_secret: hashedSecret,
			name: input.name ?? existing?.name ?? null,
			redirect_uris: encodeStringArray(redirectUris),
			scope: encodeStringArray(scope),
			metadata: serializeMetadata(metadata),
			first_party: input.firstParty ?? existing?.first_party ?? false
		} as OAuthClientCreationAttributes);
		const model = await this.clients.findByPk(input.clientId);
		if (!model) {
			throw new Error(`Unable to persist OAuth client ${input.clientId}`);
		}
		return this.toOAuthClient(model);
	}

	public override async verifyClientSecret(clientId: string, clientSecret: string | null): Promise<boolean> {
		const model = await this.clients.findByPk(clientId);
		if (!model) {
			return false;
		}
		if (!model.client_secret) {
			return !clientSecret || clientSecret.length === 0;
		}
		if (!clientSecret) {
			return false;
		}
		return bcrypt.compare(clientSecret, model.client_secret);
	}

	public override async createAuthCode(code: AuthCode): Promise<void> {
		await this.codes.create({
			code: code.code,
			client_id: code.clientId,
			user_id: normalizeNumericUserId(code.userId),
			redirect_uri: code.redirectUri ?? '',
			scope: encodeStringArray(code.scope),
			code_challenge: code.codeChallenge ?? null,
			code_challenge_method: code.codeChallengeMethod ?? null,
			expires: code.expiresAt,
			metadata: serializeMetadata(code.metadata)
		} as OAuthCodeCreationAttributes);
	}

	public override async consumeAuthCode(code: string, clientId?: string): Promise<AuthCode | null> {
		const sequelize = this.codes.sequelize;
		if (!sequelize) {
			throw new Error('Code model is not bound to a Sequelize instance');
		}
		return sequelize.transaction(
			{ isolationLevel: Transaction.ISOLATION_LEVELS.READ_COMMITTED },
			async (transaction) => {
				const where: Record<string, unknown> = { code };
				if (clientId) {
					where.client_id = clientId;
				}
				const model = await this.codes.findOne({
					where,
					transaction,
					lock: true
				});
				if (!model) {
					return null;
				}
				await model.destroy({ transaction });
				if (model.expires.getTime() <= Date.now()) {
					return null;
				}
				return this.toAuthCode(model);
			}
		);
	}

	public override async close(): Promise<void> {
		return;
	}

	private toOAuthClient(model: OAuthClientModel): OAuthClient {
		return {
			clientId: model.client_id,
			hasSecret: Boolean(model.client_secret),
			name: model.name ?? undefined,
			redirectUris: decodeStringArray(model.redirect_uris),
			scope: decodeStringArray(model.scope),
			metadata: parseMetadata(model.metadata),
			firstParty: model.first_party ?? false
		};
	}

	private toAuthCode(model: OAuthCodeModel): AuthCode {
		return {
			code: model.code,
			clientId: model.client_id,
			userId: String(model.user_id),
			redirectUri: model.redirect_uri,
			scope: decodeStringArray(model.scope),
			codeChallenge: model.code_challenge ?? undefined,
			codeChallengeMethod: model.code_challenge_method ?? undefined,
			expiresAt: model.expires,
			metadata: parseMetadata(model.metadata)
		};
	}
}
