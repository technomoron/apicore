import { DataTypes, Model, type Optional, type Sequelize } from 'sequelize';

import { integerIdType, tableOptions } from '../sequelize-utils.js';

export { integerIdType, tableOptions } from '../sequelize-utils.js';

export interface OAuthClientAttributes {
	client_id: string;
	client_secret: string;
	name: string | null;
	redirect_uris: string;
	scope: string;
	metadata: string | null;
	first_party: boolean;
}

export type OAuthClientCreationAttributes = Optional<
	OAuthClientAttributes,
	'client_secret' | 'name' | 'scope' | 'metadata' | 'first_party'
>;

export class OAuthClientModel
	extends Model<OAuthClientAttributes, OAuthClientCreationAttributes>
	implements OAuthClientAttributes
{
	declare client_id: string;
	declare client_secret: string;
	declare name: string | null;
	declare redirect_uris: string;
	declare scope: string;
	declare metadata: string | null;
	declare first_party: boolean;
}

export function initOAuthClientModel(
	sequelize: Sequelize,
	options: { tablePrefix?: string } = {}
): typeof OAuthClientModel {
	OAuthClientModel.init(
		{
			client_id: {
				type: DataTypes.STRING(128),
				allowNull: false,
				primaryKey: true
			},
			client_secret: {
				type: DataTypes.STRING(255),
				allowNull: false,
				defaultValue: ''
			},
			name: {
				type: DataTypes.STRING(128),
				allowNull: true,
				defaultValue: null
			},
			redirect_uris: {
				type: DataTypes.TEXT,
				allowNull: false,
				defaultValue: '[]'
			},
			scope: {
				type: DataTypes.TEXT,
				allowNull: false,
				defaultValue: '[]'
			},
			metadata: {
				type: DataTypes.TEXT,
				allowNull: true,
				defaultValue: null
			},
			first_party: {
				type: DataTypes.BOOLEAN,
				allowNull: false,
				defaultValue: false
			}
		},
		{
			...tableOptions(sequelize, 'oauth_clients', options.tablePrefix, {
				timestamps: false
			})
		}
	);

	return OAuthClientModel;
}

export interface OAuthCodeAttributes {
	code: string;
	client_id: string;
	user_id: number;
	redirect_uri: string;
	scope: string;
	code_challenge: string | null;
	code_challenge_method: 'plain' | 'S256' | null;
	expires: Date;
	metadata: string | null;
}

export type OAuthCodeCreationAttributes = Optional<
	OAuthCodeAttributes,
	'code_challenge' | 'code_challenge_method' | 'metadata'
>;

export class OAuthCodeModel
	extends Model<OAuthCodeAttributes, OAuthCodeCreationAttributes>
	implements OAuthCodeAttributes
{
	declare code: string;
	declare client_id: string;
	declare user_id: number;
	declare redirect_uri: string;
	declare scope: string;
	declare code_challenge: string | null;
	declare code_challenge_method: 'plain' | 'S256' | null;
	declare expires: Date;
	declare metadata: string | null;
}

export function initOAuthCodeModel(
	sequelize: Sequelize,
	options: { tablePrefix?: string } = {}
): typeof OAuthCodeModel {
	const idType = integerIdType(sequelize);

	OAuthCodeModel.init(
		{
			code: {
				type: DataTypes.STRING(128),
				allowNull: false,
				primaryKey: true
			},
			client_id: { type: DataTypes.STRING(128), allowNull: false },
			user_id: { type: idType, allowNull: false },
			redirect_uri: { type: DataTypes.TEXT, allowNull: false },
			scope: {
				type: DataTypes.TEXT,
				allowNull: false,
				defaultValue: '[]'
			},
			code_challenge: {
				type: DataTypes.STRING(255),
				allowNull: true,
				defaultValue: null
			},
			code_challenge_method: {
				type: DataTypes.STRING(10),
				allowNull: true,
				defaultValue: null
			},
			expires: { type: DataTypes.DATE, allowNull: false },
			metadata: {
				type: DataTypes.TEXT,
				allowNull: true,
				defaultValue: null
			}
		},
		{
			...tableOptions(sequelize, 'oauth_codes', options.tablePrefix, {
				timestamps: false
			})
		}
	);

	return OAuthCodeModel;
}
