import bcrypt from 'bcryptjs';

import { normalizeComparableUserId } from '../auth-api/user-id.js';

import { OAuthStore, type AuthCode, type OAuthClient } from './base.js';

interface StoredClient extends OAuthClient {
	clientSecret?: string;
}

export interface MemoryOAuthStoreOptions {
	bcryptRounds?: number;
	maxClients?: number;
	maxAuthCodes?: number;
}

function cloneClient(client: StoredClient | undefined): OAuthClient | null {
	if (!client) {
		return null;
	}
	return {
		clientId: client.clientId,
		hasSecret: Boolean(client.clientSecret),
		name: client.name,
		redirectUris: [...client.redirectUris],
		scope: client.scope ? [...client.scope] : undefined,
		metadata: client.metadata ? JSON.parse(JSON.stringify(client.metadata)) : undefined,
		firstParty: client.firstParty
	};
}

function cloneCode(code: AuthCode): AuthCode {
	return {
		...code,
		userId: normalizeComparableUserId(code.userId),
		scope: code.scope ? [...code.scope] : undefined,
		expiresAt: new Date(code.expiresAt),
		metadata: code.metadata ? { ...code.metadata } : undefined
	};
}

export class MemoryOAuthStore extends OAuthStore {
	private readonly clients = new Map<string, StoredClient>();
	private readonly codes = new Map<string, AuthCode>();
	private readonly bcryptRounds: number;
	private readonly maxClients?: number;
	private readonly maxAuthCodes?: number;

	constructor(options: MemoryOAuthStoreOptions = {}) {
		super();
		this.bcryptRounds = options.bcryptRounds ?? 12;
		this.maxClients =
			typeof options.maxClients === 'number' && Number.isFinite(options.maxClients) && options.maxClients > 0
				? Math.floor(options.maxClients)
				: undefined;
		this.maxAuthCodes =
			typeof options.maxAuthCodes === 'number' &&
			Number.isFinite(options.maxAuthCodes) &&
			options.maxAuthCodes > 0
				? Math.floor(options.maxAuthCodes)
				: undefined;
	}

	public override async getClient(clientId: string): Promise<OAuthClient | null> {
		return cloneClient(this.clients.get(clientId));
	}

	public override async createClient(input: OAuthClient): Promise<OAuthClient> {
		const clientSecret = input.clientSecret ? await bcrypt.hash(input.clientSecret, this.bcryptRounds) : '';
		const stored: StoredClient = {
			clientId: input.clientId,
			clientSecret,
			name: input.name,
			redirectUris: [...input.redirectUris],
			scope: input.scope ? [...input.scope] : undefined,
			metadata: input.metadata ? { ...input.metadata } : undefined,
			firstParty: input.firstParty
		};
		this.clients.set(stored.clientId, stored);
		this.enforceClientCapacity();
		return cloneClient(stored)!;
	}

	public override async verifyClientSecret(clientId: string, secret: string | null): Promise<boolean> {
		const client = this.clients.get(clientId);
		if (!client) {
			return false;
		}
		if (!client.clientSecret) {
			return !secret || secret.length === 0;
		}
		if (!secret) {
			return false;
		}
		return bcrypt.compare(secret, client.clientSecret);
	}

	public override async createAuthCode(code: AuthCode): Promise<void> {
		const record: AuthCode = {
			...code,
			userId: normalizeComparableUserId(code.userId),
			scope: code.scope ? [...code.scope] : undefined,
			expiresAt: code.expiresAt,
			metadata: code.metadata ? { ...code.metadata } : undefined
		};
		this.codes.set(record.code, record);
		this.enforceCodeCapacity();
	}

	public override async consumeAuthCode(code: string, clientId?: string): Promise<AuthCode | null> {
		const record = this.codes.get(code);
		if (!record) {
			return null;
		}
		if (clientId && record.clientId !== clientId) {
			return null;
		}
		if (record.expiresAt.getTime() <= Date.now()) {
			this.codes.delete(code);
			return null;
		}
		this.codes.delete(code);
		return cloneCode(record);
	}

	public override async close(): Promise<void> {
		return;
	}

	private enforceClientCapacity(): void {
		if (!this.maxClients) {
			return;
		}
		while (this.clients.size > this.maxClients) {
			const oldest = this.clients.keys().next().value;
			if (!oldest) {
				return;
			}
			console.warn(
				`[MemoryOAuthStore] Client capacity exceeded (max ${this.maxClients}); evicting oldest client "${oldest}".`
			);
			this.clients.delete(oldest);
		}
	}

	private enforceCodeCapacity(): void {
		if (!this.maxAuthCodes) {
			return;
		}
		while (this.codes.size > this.maxAuthCodes) {
			const oldest = this.codes.keys().next().value;
			if (!oldest) {
				return;
			}
			this.codes.delete(oldest);
		}
	}
}
