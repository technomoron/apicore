import { normalizeNumericUserId } from '../auth-api/user-id.js';

import { UserStore } from './base.js';

import type { CreateUserInput, PublicUserMapper, UpdateUserInput } from './types.js';
import type { AuthIdentifier } from '../auth-api/types.js';

export interface MemoryUserAttributes extends Record<string, unknown> {
	user_id: number;
	login: string;
	email: string;
	password: string;
}

export type MemoryPublicUser<UserAttributes extends MemoryUserAttributes = MemoryUserAttributes> = Omit<
	UserAttributes,
	'password'
>;

export interface MemoryUserStoreOptions<
	UserAttributes extends MemoryUserAttributes = MemoryUserAttributes,
	PublicUserShape extends Omit<UserAttributes, 'password'> = Omit<UserAttributes, 'password'>
> {
	bcryptRounds?: number;
	bcryptPepper?: string;
	toPublic?: PublicUserMapper<UserAttributes, PublicUserShape>;
	userIdFactory?: () => number;
	startingUserId?: number;
	maxUsers?: number;
}

function cloneUser<UserAttributes extends MemoryUserAttributes>(user: UserAttributes): UserAttributes {
	return { ...user };
}

export class MemoryUserStore<
	UserAttributes extends MemoryUserAttributes = MemoryUserAttributes,
	PublicUserShape extends Omit<UserAttributes, 'password'> = Omit<UserAttributes, 'password'>
> extends UserStore<UserAttributes, PublicUserShape> {
	private readonly usersById = new Map<number, UserAttributes>();
	private readonly loginToId = new Map<string, number>();
	private readonly emailToId = new Map<string, number>();
	private readonly userIdFactory: () => number;
	private readonly maxUsers?: number;
	private nextUserId: number;

	constructor(options: MemoryUserStoreOptions<UserAttributes, PublicUserShape> = {}) {
		super({
			toPublic: options.toPublic,
			bcryptRounds: options.bcryptRounds,
			bcryptPepper: options.bcryptPepper
		});
		this.nextUserId = Number.isFinite(options.startingUserId) ? Number(options.startingUserId) : 1;
		this.maxUsers =
			typeof options.maxUsers === 'number' && Number.isFinite(options.maxUsers) && options.maxUsers > 0
				? Math.floor(options.maxUsers)
				: undefined;
		this.userIdFactory =
			options.userIdFactory ??
			(() => {
				const id = this.nextUserId;
				this.nextUserId += 1;
				return id;
			});
	}

	public override async findUser(identifier: AuthIdentifier | string): Promise<UserAttributes | null> {
		if (typeof identifier === 'number') {
			const user = this.usersById.get(identifier);
			return user ? cloneUser(user) : null;
		}
		if (typeof identifier === 'string') {
			const numeric = /^\d+$/.test(identifier) ? Number(identifier) : null;
			if (numeric !== null) {
				const user = this.usersById.get(numeric);
				if (user) {
					return cloneUser(user);
				}
			}
			const loginId = this.loginToId.get(identifier);
			if (loginId !== undefined) {
				const loginUser = this.usersById.get(loginId);
				if (loginUser) return cloneUser(loginUser);
			}
			const emailId = this.emailToId.get(identifier);
			if (emailId !== undefined) {
				const emailUser = this.usersById.get(emailId);
				if (emailUser) return cloneUser(emailUser);
			}
		}
		return null;
	}

	public override async findById(id: AuthIdentifier): Promise<UserAttributes | null> {
		try {
			const numeric = normalizeNumericUserId(id);
			const user = this.usersById.get(numeric);
			return user ? cloneUser(user) : null;
		} catch {
			return null;
		}
	}

	public override async findByLoginOrEmail(loginOrEmail: string): Promise<UserAttributes | null> {
		const loginId = this.loginToId.get(loginOrEmail);
		if (loginId !== undefined) {
			const loginUser = this.usersById.get(loginId);
			if (loginUser) return cloneUser(loginUser);
		}
		const emailId = this.emailToId.get(loginOrEmail);
		if (emailId !== undefined) {
			const emailUser = this.usersById.get(emailId);
			if (emailUser) return cloneUser(emailUser);
		}
		return null;
	}

	public override async createUser(input: CreateUserInput): Promise<UserAttributes> {
		const normalizedInput = this.normalizeUserInput(input);
		const providedId = (input as Partial<MemoryUserAttributes>).user_id;
		const userId =
			typeof providedId === 'number' && Number.isFinite(providedId) ? providedId : this.userIdFactory();
		if (this.usersById.has(userId)) {
			throw new Error(`User ${userId} already exists`);
		}
		if (this.maxUsers !== undefined && this.usersById.size >= this.maxUsers) {
			throw new Error('MemoryUserStore maxUsers limit reached');
		}

		if (this.loginToId.has(normalizedInput.login)) {
			throw new Error(`User with login ${normalizedInput.login} already exists`);
		}
		if (this.emailToId.has(normalizedInput.email)) {
			throw new Error(`User with email ${normalizedInput.email} already exists`);
		}

		const passwordHash = normalizedInput.password ? await this.hashPassword(normalizedInput.password) : '';
		const record = {
			...(normalizedInput as Record<string, unknown>),
			user_id: userId,
			password: passwordHash
		} as UserAttributes;

		this.persistUser(record);
		if (typeof providedId === 'number' && Number.isFinite(providedId)) {
			this.nextUserId = Math.max(this.nextUserId, providedId + 1);
		}
		return cloneUser(record);
	}

	public override async upsertUser(input: CreateUserInput): Promise<UserAttributes> {
		const normalizedInput = this.normalizeUserInput(input);
		const providedId = (input as Partial<MemoryUserAttributes>).user_id;
		if (providedId !== undefined) {
			const existing = this.usersById.get(providedId);
			if (!existing) {
				throw new Error(`User ${providedId} not found`);
			}
			const updates: UserAttributes = {
				...existing,
				...(normalizedInput as Record<string, unknown>)
			} as UserAttributes;
			if (updates.login !== existing.login) {
				const loginOwner = this.loginToId.get(updates.login);
				if (loginOwner !== undefined && loginOwner !== existing.user_id) {
					throw new Error(`User with login ${updates.login} already exists`);
				}
			}
			if (updates.email !== existing.email) {
				const emailOwner = this.emailToId.get(updates.email);
				if (emailOwner !== undefined && emailOwner !== existing.user_id) {
					throw new Error(`User with email ${updates.email} already exists`);
				}
			}
			if (normalizedInput.password && normalizedInput.password.length > 0) {
				updates.password = await this.hashPassword(normalizedInput.password);
			} else {
				updates.password = existing.password;
			}
			this.persistUser(updates);
			return cloneUser(updates);
		}

		return this.createUser(input);
	}

	public override async updateUser(id: AuthIdentifier, patch: UpdateUserInput): Promise<UserAttributes> {
		const user = await this.findById(id);
		if (!user) {
			throw new Error(`User ${String(id)} not found`);
		}
		const updates: UserAttributes = {
			...user,
			...(patch as Record<string, unknown>)
		} as UserAttributes;
		if (patch.password && patch.password.length > 0) {
			updates.password = await this.hashPassword(patch.password);
		} else {
			updates.password = user.password;
		}
		this.persistUser(updates);
		return cloneUser(updates);
	}

	public override async setPasswordHash(id: AuthIdentifier, hash: string): Promise<void> {
		const user = await this.findById(id);
		if (!user) {
			throw new Error(`User ${String(id)} not found`);
		}
		const updates: UserAttributes = { ...user, password: hash };
		this.persistUser(updates);
	}

	public override getPasswordHash(user: UserAttributes): string | null {
		return user.password;
	}

	public override getUserId(user: UserAttributes): AuthIdentifier {
		return user.user_id;
	}

	private persistUser(user: UserAttributes): void {
		const snapshot = { ...user } as UserAttributes;
		this.usersById.set(user.user_id, snapshot);
		for (const [login, id] of [...this.loginToId.entries()]) {
			if (id === user.user_id && login !== user.login) {
				this.loginToId.delete(login);
			}
		}
		for (const [email, id] of [...this.emailToId.entries()]) {
			if (id === user.user_id && email !== user.email) {
				this.emailToId.delete(email);
			}
		}
		this.loginToId.set(user.login, user.user_id);
		this.emailToId.set(user.email, user.user_id);
	}
}
