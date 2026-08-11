export interface BcryptHasherOptions {
	rounds?: number;
	pepper?: string;
}

export type CreateUserInput = Record<string, unknown> & {
	login: string;
	email: string;
	password?: string;
};

export type UpdateUserInput = Partial<CreateUserInput>;

export type PublicUserMapper<User, PublicUser> = (user: User) => PublicUser;
