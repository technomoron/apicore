import { Op, Transaction, type ModelStatic, type Sequelize } from 'sequelize';

import { normalizeNumericUserId } from '../auth-api/user-id.js';

import { PasskeyStore } from './base.js';
import {
	PasskeyChallengeModel,
	PasskeyCredentialModel,
	initPasskeyChallengeModel,
	initPasskeyCredentialModel
} from './models.js';

import type { PasskeyChallengeRecord, PasskeyUserDescriptor, StoredPasskeyCredential } from './types.js';
import type { AuthIdentifier } from '../auth-api/types.js';

function encodeCredentialId(value: Buffer | string): string {
	return Buffer.isBuffer(value) ? value.toString('base64') : value;
}

export interface SequelizePasskeyStoreOptions {
	sequelize: Sequelize;
	tablePrefix?: string;
	credentialModel?: ModelStatic<PasskeyCredentialModel>;
	challengeModel?: ModelStatic<PasskeyChallengeModel>;
	credentialModelFactory?: (
		sequelize: Sequelize,
		options?: { tablePrefix?: string }
	) => ModelStatic<PasskeyCredentialModel>;
	challengeModelFactory?: (
		sequelize: Sequelize,
		options?: { tablePrefix?: string }
	) => ModelStatic<PasskeyChallengeModel>;
	resolveUser: (params: { userId?: AuthIdentifier; login?: string }) => Promise<PasskeyUserDescriptor | null>;
}

export class SequelizePasskeyStore extends PasskeyStore {
	private readonly resolveUserFn: SequelizePasskeyStoreOptions['resolveUser'];
	private readonly credentials: ModelStatic<PasskeyCredentialModel>;
	private readonly challenges: ModelStatic<PasskeyChallengeModel>;

	constructor(options: SequelizePasskeyStoreOptions) {
		super();
		if (!options?.sequelize) {
			throw new Error('SequelizePasskeyStore requires an initialised Sequelize instance');
		}
		this.resolveUserFn = options.resolveUser;
		this.credentials =
			options.credentialModel ??
			(options.credentialModelFactory ?? initPasskeyCredentialModel)(options.sequelize, {
				tablePrefix: options.tablePrefix
			});
		this.challenges =
			options.challengeModel ??
			(options.challengeModelFactory ?? initPasskeyChallengeModel)(options.sequelize, {
				tablePrefix: options.tablePrefix
			});
	}

	public override async resolveUser(params: {
		userId?: AuthIdentifier;
		login?: string;
	}): Promise<PasskeyUserDescriptor | null> {
		return this.resolveUserFn(params);
	}

	public override async listUserCredentials(userId: AuthIdentifier): Promise<StoredPasskeyCredential[]> {
		const models = await this.credentials.findAll({
			where: { userId: normalizeNumericUserId(userId) }
		});
		return models.map((model) => this.toStoredCredential(model));
	}

	public override async deleteCredential(credentialId: Buffer | string): Promise<boolean> {
		const encoded = Buffer.isBuffer(credentialId) ? credentialId.toString('base64') : credentialId;
		const deleted = await this.credentials.destroy({
			where: { credentialId: encoded }
		});
		return deleted > 0;
	}

	public override async findCredentialById(credentialId: Buffer): Promise<StoredPasskeyCredential | null> {
		const model = await this.credentials.findByPk(encodeCredentialId(credentialId));
		return model ? this.toStoredCredential(model) : null;
	}

	public override async saveCredential(record: StoredPasskeyCredential): Promise<void> {
		await this.credentials.upsert({
			credentialId: record.credentialId,
			userId: normalizeNumericUserId(record.userId),
			publicKey: record.publicKey,
			counter: record.counter,
			transports: record.transports ?? null,
			backedUp: record.backedUp,
			deviceType: record.deviceType,
			label: record.label ?? null,
			createdDomain: record.createdDomain ?? null,
			createdUserAgent: record.createdUserAgent ?? null,
			createdBrowser: record.createdBrowser ?? null,
			createdOs: record.createdOs ?? null,
			createdDevice: record.createdDevice ?? null,
			createdIp: record.createdIp ?? null
		});
	}

	public override async updateCredentialCounter(credentialId: Buffer, counter: number): Promise<void> {
		await this.credentials.update({ counter }, { where: { credentialId: encodeCredentialId(credentialId) } });
	}

	public override async saveChallenge(record: PasskeyChallengeRecord): Promise<void> {
		await this.challenges.upsert({
			challenge: record.challenge,
			action: record.action,
			userId: record.userId !== undefined ? normalizeNumericUserId(record.userId) : null,
			login: record.login ?? null,
			expiresAt: record.expiresAt
		});
	}

	public override async getChallenge(challenge: string): Promise<PasskeyChallengeRecord | null> {
		const model = await this.challenges.findByPk(challenge);
		return model ? this.toChallengeRecord(model) : null;
	}

	public override async consumeChallenge(challenge: string): Promise<PasskeyChallengeRecord | null> {
		const sequelize = this.challenges.sequelize;
		if (!sequelize) {
			throw new Error('Challenge model is not bound to a Sequelize instance');
		}
		return sequelize.transaction(
			{ isolationLevel: Transaction.ISOLATION_LEVELS.READ_COMMITTED },
			async (transaction) => {
				const model = await this.challenges.findByPk(challenge, {
					transaction,
					lock: true
				});
				if (!model) {
					return null;
				}
				await model.destroy({ transaction });
				return this.toChallengeRecord(model);
			}
		);
	}

	public override async cleanupChallenges(now: Date): Promise<void> {
		await this.challenges.destroy({
			where: { expiresAt: { [Op.lte]: now } }
		});
	}

	private toChallengeRecord(model: PasskeyChallengeModel): PasskeyChallengeRecord {
		return {
			challenge: model.challenge,
			action: model.action as PasskeyChallengeRecord['action'],
			userId: model.userId !== null ? String(model.userId) : undefined,
			login: model.login ?? undefined,
			expiresAt: model.expiresAt
		};
	}

	private toStoredCredential(model: PasskeyCredentialModel): StoredPasskeyCredential {
		return {
			userId: String(model.userId),
			credentialId: model.credentialId,
			publicKey: model.publicKey,
			counter: model.counter,
			transports: (model.transports ?? undefined) as StoredPasskeyCredential['transports'],
			backedUp: model.backedUp,
			deviceType: model.deviceType as StoredPasskeyCredential['deviceType'],
			label: model.label ?? undefined,
			createdDomain: model.createdDomain ?? undefined,
			createdUserAgent: model.createdUserAgent ?? undefined,
			createdBrowser: model.createdBrowser ?? undefined,
			createdOs: model.createdOs ?? undefined,
			createdDevice: model.createdDevice ?? undefined,
			createdIp: model.createdIp ?? undefined,
			createdAt: model.createdAt ?? undefined,
			updatedAt: model.updatedAt ?? undefined
		};
	}
}
