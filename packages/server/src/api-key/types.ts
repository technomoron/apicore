import type { ApiKey } from '../api-module.js';
import type { AuthIdentifier } from '../auth-api/types.js';

export interface ApiKeyRecord extends ApiKey {
	uid: AuthIdentifier;
	euid?: AuthIdentifier;
	/** Non-secret key handle safe for logs and diagnostics. */
	id?: string;
	/** API key secret used as the bearer credential. Never return this from lookups. */
	secret: string;
	/** Opaque application-owned metadata. ApiCore does not enforce policy from this object. */
	meta?: Record<string, unknown>;
}

export interface ApiKeyFile {
	version: 1;
	keys: ApiKeyRecord[];
}

export interface StoredApiKey extends ApiKey {
	id?: string;
	uid: AuthIdentifier;
	euid?: AuthIdentifier;
	meta?: Record<string, unknown>;
}

export interface ApiKeyStore {
	get(secret: string): Promise<StoredApiKey | null>;
	list?(): Promise<StoredApiKey[]>;
	close?(): Promise<void>;
}
