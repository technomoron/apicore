import { createHmac } from 'node:crypto';

import bcrypt from 'bcryptjs';

import type { CreateUserInput, PublicUserMapper, UpdateUserInput } from './types.js';
import type { AuthIdentifier } from '../auth-api/types.js';

/** Base contract for user persistence backends. */
export abstract class UserStore<User, PublicUser> {
	protected readonly toPublicUser: PublicUserMapper<User, PublicUser>;
	private readonly bcryptRounds: number;
	private readonly bcryptPepper?: string;

	constructor(
		opts: {
			toPublic?: PublicUserMapper<User, PublicUser>;
			bcryptRounds?: number;
			bcryptPepper?: string;
		} = {}
	) {
		this.toPublicUser = opts.toPublic ?? ((u) => u as unknown as PublicUser);
		const rounds =
			typeof opts.bcryptRounds === 'number' && Number.isFinite(opts.bcryptRounds)
				? Math.max(4, Math.floor(opts.bcryptRounds))
				: 12;
		if (rounds < 10) {
			console.warn(
				`[apicore] bcryptRounds is set to ${rounds}, which is dangerously low. ` +
					'Use at least 10 rounds in production to resist brute-force attacks.'
			);
		}
		this.bcryptRounds = rounds;
		this.bcryptPepper =
			typeof opts.bcryptPepper === 'string' && opts.bcryptPepper.length > 0 ? opts.bcryptPepper : undefined;
	}

	private applyPepper(plain: string): string {
		if (!this.bcryptPepper) {
			return plain;
		}
		return createHmac('sha256', this.bcryptPepper).update(plain).digest('hex');
	}

	protected async hashPassword(plain: string): Promise<string> {
		const candidate = this.applyPepper(plain);
		return bcrypt.hash(candidate, this.bcryptRounds);
	}

	public async verifyPassword(plain: string, hashed: string): Promise<boolean> {
		const candidate = this.applyPepper(plain);
		return bcrypt.compare(candidate, hashed);
	}

	protected normalizeUserInput(input: Partial<CreateUserInput>): CreateUserInput {
		const login = typeof input.login === 'string' ? input.login.trim() : '';
		const email = typeof input.email === 'string' ? input.email.trim() : '';
		if (!login || !email) {
			throw new Error('login and email are required');
		}
		const password = typeof input.password === 'string' ? input.password : undefined;
		return { ...input, login, email, password };
	}

	/** Find a user by id/login/email identifier. */
	public abstract findUser(identifier: AuthIdentifier | string): Promise<User | null>;
	/** Find a user by primary id only. */
	public abstract findById(id: AuthIdentifier): Promise<User | null>;
	/** Find a user by login or email value. */
	public abstract findByLoginOrEmail(loginOrEmail: string): Promise<User | null>;
	/** Create a new user record. */
	public abstract createUser(input: CreateUserInput): Promise<User>;
	// Upserts by explicit user identifier only; if no id is provided this creates a new user.
	public abstract upsertUser(input: CreateUserInput): Promise<User>;
	/** Update selected user fields. */
	public abstract updateUser(id: AuthIdentifier, patch: UpdateUserInput): Promise<User>;
	/** Persist a password hash for the given user id. */
	public abstract setPasswordHash(id: AuthIdentifier, hash: string): Promise<void>;
	/** Extract the password hash from a user record. */
	public abstract getPasswordHash(user: User): string | null;
	/** Extract the stable user identifier from a user record. */
	public abstract getUserId(user: User): AuthIdentifier;

	public toPublic(user: User): PublicUser {
		const mapped = this.toPublicUser(user);
		if (mapped && typeof mapped === 'object') {
			const rest = { ...(mapped as Record<string, unknown>) };
			delete rest.password;
			return rest as PublicUser;
		}
		return mapped;
	}
}

export type { CreateUserInput, UpdateUserInput, PublicUserMapper } from './types.js';
