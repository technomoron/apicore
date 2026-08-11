import {
	CreationOptional,
	DataTypes,
	Model,
	Op,
	UniqueConstraintError,
	type InferAttributes,
	type InferCreationAttributes,
	type WhereOptions,
	type ModelStatic,
	type Sequelize
} from 'sequelize';

import { normalizeNumericUserId } from '../auth-api/user-id.js';
import { integerIdType, tableOptions } from '../sequelize-utils.js';

import { UserStore } from './base.js';

import type { CreateUserInput, PublicUserMapper, UpdateUserInput } from './types.js';
import type { AuthIdentifier } from '../auth-api/types.js';

export class AuthUserModel
	extends Model<InferAttributes<AuthUserModel>, InferCreationAttributes<AuthUserModel>>
	implements InferAttributes<AuthUserModel>
{
	declare user_id: CreationOptional<number>;
	declare login: string;
	declare email: string;
	declare password: string;
}

export type AuthUserAttributes = InferAttributes<AuthUserModel>;
export type AuthUserCreationAttributes = InferCreationAttributes<AuthUserModel>;

export function initAuthUserModel(sequelize: Sequelize, options: { tablePrefix?: string } = {}): typeof AuthUserModel {
	const idType = integerIdType(sequelize);

	AuthUserModel.init(
		{
			user_id: {
				type: idType,
				autoIncrement: true,
				allowNull: false,
				primaryKey: true
			},
			login: {
				type: DataTypes.STRING(64),
				allowNull: false,
				unique: true
			},
			email: {
				type: DataTypes.STRING(100),
				allowNull: false,
				unique: true
			},
			password: {
				type: DataTypes.STRING(255),
				allowNull: false
			}
		},
		{
			...tableOptions(sequelize, 'users', options.tablePrefix, {
				timestamps: false
			})
		}
	);

	return AuthUserModel;
}

export type GenericUserModel = Model<Record<string, unknown>, Record<string, unknown>>;
export type GenericUserModelStatic = ModelStatic<GenericUserModel>;

export interface SequelizeUserStoreOptions<
	UserAttributes extends AuthUserAttributes = AuthUserAttributes,
	PublicUserShape extends Omit<UserAttributes, 'password'> = Omit<UserAttributes, 'password'>
> {
	bcryptRounds?: number;
	bcryptPepper?: string;
	sequelize: Sequelize;
	tablePrefix?: string;
	userModel?: GenericUserModelStatic;
	userModelFactory?: (sequelize: Sequelize, options?: { tablePrefix?: string }) => GenericUserModelStatic;
	recordMapper?: (model: GenericUserModel) => UserAttributes;
	toPublic?: PublicUserMapper<UserAttributes, PublicUserShape>;
}

export class SequelizeUserStore<
	UserAttributes extends AuthUserAttributes = AuthUserAttributes,
	PublicUserShape extends Omit<UserAttributes, 'password'> = Omit<UserAttributes, 'password'>
> extends UserStore<UserAttributes, PublicUserShape> {
	public readonly Users: GenericUserModelStatic;
	private readonly recordMapper: (model: GenericUserModel) => UserAttributes;

	constructor(options: SequelizeUserStoreOptions<UserAttributes, PublicUserShape>) {
		super({
			toPublic: options.toPublic,
			bcryptRounds: options.bcryptRounds,
			bcryptPepper: options.bcryptPepper
		});
		if (!options?.sequelize) {
			throw new Error('SequelizeUserStore requires a configured Sequelize instance');
		}
		this.Users = options.userModel
			? options.userModel
			: (options.userModelFactory ?? initAuthUserModel)(options.sequelize, {
					tablePrefix: options.tablePrefix
				});
		this.recordMapper =
			options.recordMapper ??
			((model: GenericUserModel) =>
				SequelizeUserStore.mapModelToUser(model as unknown as Model<AuthUserAttributes>) as UserAttributes);
	}

	public override async findUser(identifier: AuthIdentifier | string): Promise<UserAttributes | null> {
		const where: WhereOptions[] = [];
		try {
			where.push({ user_id: this.normalizeUserId(identifier) });
		} catch {
			// ignore
		}
		if (typeof identifier === 'string') {
			where.push({ login: identifier });
			where.push({ email: identifier });
		}
		if (where.length === 0) {
			return null;
		}
		const model = await this.Users.findOne({ where: { [Op.or]: where } });
		return model ? this.toUserRecord(model) : null;
	}

	public override async findById(id: AuthIdentifier): Promise<UserAttributes | null> {
		try {
			const model = await this.Users.findByPk(this.normalizeUserId(id));
			return model ? this.toUserRecord(model) : null;
		} catch {
			return null;
		}
	}

	public override async findByLoginOrEmail(loginOrEmail: string): Promise<UserAttributes | null> {
		const model = await this.Users.findOne({
			where: {
				[Op.or]: [{ login: loginOrEmail }, { email: loginOrEmail }]
			}
		});
		return model ? this.toUserRecord(model) : null;
	}

	public override async createUser(input: CreateUserInput): Promise<UserAttributes> {
		const normalized = this.normalizeUserInput(input);
		const { password, ...rest } = normalized;
		const defaults: Partial<AuthUserCreationAttributes> = {
			...rest,
			password: password ? await this.hashPassword(password) : ''
		};
		const providedId = (input as Partial<AuthUserAttributes>).user_id;
		if (providedId !== undefined && providedId !== null && Number.isFinite(providedId)) {
			defaults.user_id = Number(providedId);
		}
		try {
			const model = await this.Users.create(defaults as AuthUserCreationAttributes);
			return this.toUserRecord(model);
		} catch (error) {
			if (error instanceof UniqueConstraintError) {
				throw new Error(`User with login ${rest.login} or email ${rest.email} already exists`, { cause: error });
			}
			throw error;
		}
	}

	public override async upsertUser(input: CreateUserInput): Promise<UserAttributes> {
		const normalized = this.normalizeUserInput(input);
		const providedId = (input as Partial<AuthUserAttributes>).user_id;
		if (providedId !== undefined) {
			const model = await this.Users.findByPk(Number(providedId));
			if (!model) {
				throw new Error(`User ${String(providedId)} not found`);
			}

			const next: Record<string, unknown> = { ...normalized };
			if (normalized.password && normalized.password.length > 0) {
				next.password = await this.hashPassword(normalized.password);
			} else {
				delete next.password;
			}
			await model.set(next);
			try {
				await model.save();
			} catch (error) {
				if (error instanceof UniqueConstraintError) {
					throw new Error(`User with login ${normalized.login} or email ${normalized.email} already exists`, {
						cause: error
					});
				}
				throw error;
			}
			return this.toUserRecord(model);
		}

		return this.createUser(input);
	}

	public override async updateUser(id: AuthIdentifier, patch: UpdateUserInput): Promise<UserAttributes> {
		const model = await this.Users.findByPk(this.normalizeUserId(id));
		if (!model) {
			throw new Error(`User ${String(id)} not found`);
		}
		const updates: Record<string, unknown> = { ...patch };
		if (patch.password && patch.password.length > 0) {
			updates.password = await this.hashPassword(patch.password);
		} else {
			delete updates.password;
		}
		await model.set(updates);
		try {
			await model.save();
		} catch (error) {
			if (error instanceof UniqueConstraintError) {
				throw new Error(`User with login or email already exists`, { cause: error });
			}
			throw error;
		}
		return this.toUserRecord(model);
	}

	public override async setPasswordHash(id: AuthIdentifier, hash: string): Promise<void> {
		const [affected] = await this.Users.update(
			{ password: hash },
			{ where: { user_id: this.normalizeUserId(id) } }
		);
		if (affected === 0) {
			throw new Error(`User ${String(id)} not found`);
		}
	}

	public override getPasswordHash(user: UserAttributes): string | null {
		return user.password;
	}

	public override getUserId(user: UserAttributes): AuthIdentifier {
		return user.user_id;
	}

	protected toUserRecord(model: GenericUserModel): UserAttributes {
		return this.recordMapper(model);
	}

	private static mapModelToUser(model: Model<AuthUserAttributes>): AuthUserAttributes {
		return {
			user_id: model.get('user_id') as number,
			login: model.get('login') as string,
			email: model.get('email') as string,
			password: model.get('password') as string
		};
	}

	private normalizeUserId(identifier: AuthIdentifier): number {
		return normalizeNumericUserId(identifier);
	}
}
