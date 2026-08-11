import {
	DataTypes,
	Model,
	type InferAttributes,
	type InferCreationAttributes,
	type ModelStatic,
	type Sequelize
} from 'sequelize';

import { applyTablePrefix, integerIdType } from '../sequelize-utils.js';

export class PasskeyCredentialModel extends Model<
	InferAttributes<PasskeyCredentialModel>,
	InferCreationAttributes<PasskeyCredentialModel>
> {
	declare credentialId: Buffer;
	declare userId: number;
	declare publicKey: Buffer;
	declare counter: number;
	declare transports: string[] | null;
	declare backedUp: boolean;
	declare deviceType: string;
	declare label: string | null;
	declare createdDomain: string | null;
	declare createdUserAgent: string | null;
	declare createdBrowser: string | null;
	declare createdOs: string | null;
	declare createdDevice: string | null;
	declare createdIp: string | null;
	declare createdAt?: Date;
	declare updatedAt?: Date;
}

export class PasskeyChallengeModel extends Model<
	InferAttributes<PasskeyChallengeModel>,
	InferCreationAttributes<PasskeyChallengeModel>
> {
	declare challenge: string;
	declare action: 'register' | 'authenticate';
	declare userId: number | null;
	declare login: string | null;
	declare expiresAt: Date;
	declare createdAt?: Date;
	declare updatedAt?: Date;
}

export function initPasskeyCredentialModel(
	sequelize: Sequelize,
	options: { tablePrefix?: string } = {}
): ModelStatic<PasskeyCredentialModel> {
	const idType = integerIdType(sequelize);

	return PasskeyCredentialModel.init(
		{
			credentialId: {
				field: 'credential_id',
				type: DataTypes.STRING(768),
				primaryKey: true,
				allowNull: false,
				get() {
					const raw = this.getDataValue('credentialId') as unknown as string | Buffer | null;
					if (!raw) {
						return raw as null;
					}
					if (Buffer.isBuffer(raw)) {
						return raw;
					}
					return Buffer.from(raw, 'base64');
				},
				set(value: Buffer | string) {
					const encoded = typeof value === 'string' ? value : value.toString('base64');
					this.setDataValue('credentialId', encoded as unknown as Buffer);
				}
			},
			userId: {
				field: 'user_id',
				type: idType,
				allowNull: false
			},
			publicKey: {
				field: 'public_key',
				type: DataTypes.BLOB,
				allowNull: false
			},
			counter: {
				type: DataTypes.INTEGER,
				allowNull: false,
				defaultValue: 0
			},
			transports: {
				type: DataTypes.JSON,
				allowNull: true
			},
			backedUp: {
				field: 'backed_up',
				type: DataTypes.BOOLEAN,
				allowNull: false,
				defaultValue: false
			},
			deviceType: {
				field: 'device_type',
				type: DataTypes.STRING(32),
				allowNull: false,
				defaultValue: 'multiDevice'
			},
			label: {
				type: DataTypes.STRING(120),
				allowNull: true
			},
			createdDomain: {
				field: 'created_domain',
				type: DataTypes.STRING(255),
				allowNull: true
			},
			createdUserAgent: {
				field: 'created_user_agent',
				type: DataTypes.TEXT,
				allowNull: true
			},
			createdBrowser: {
				field: 'created_browser',
				type: DataTypes.STRING(120),
				allowNull: true
			},
			createdOs: {
				field: 'created_os',
				type: DataTypes.STRING(120),
				allowNull: true
			},
			createdDevice: {
				field: 'created_device',
				type: DataTypes.STRING(120),
				allowNull: true
			},
			createdIp: {
				field: 'created_ip',
				type: DataTypes.STRING(45),
				allowNull: true
			}
		},
		{
			sequelize,
			tableName: applyTablePrefix(options.tablePrefix, 'passkey_credentials'),
			timestamps: true,
			underscored: true
		}
	);
}

export function initPasskeyChallengeModel(
	sequelize: Sequelize,
	options: { tablePrefix?: string } = {}
): ModelStatic<PasskeyChallengeModel> {
	const idType = integerIdType(sequelize);

	return PasskeyChallengeModel.init(
		{
			challenge: {
				type: DataTypes.STRING(255),
				primaryKey: true,
				allowNull: false
			},
			action: {
				type: DataTypes.STRING(16),
				allowNull: false
			},
			userId: {
				field: 'user_id',
				type: idType,
				allowNull: true
			},
			login: {
				type: DataTypes.STRING(128),
				allowNull: true
			},
			expiresAt: {
				field: 'expires_at',
				type: DataTypes.DATE,
				allowNull: false
			}
		},
		{
			sequelize,
			tableName: applyTablePrefix(options.tablePrefix, 'passkey_challenges'),
			timestamps: true,
			underscored: true,
			indexes: [{ fields: ['expires_at'] }, { fields: ['user_id'] }]
		}
	);
}
