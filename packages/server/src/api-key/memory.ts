import { normalizeApiKeyRecords, toStoredApiKey } from './base.js';

import type { ApiKeyRecord, ApiKeyStore, StoredApiKey } from './types.js';

export interface MemoryApiKeyStoreOptions {
	keys?: ApiKeyRecord[];
}

export class MemoryApiKeyStore implements ApiKeyStore {
	private readonly keys = new Map<string, StoredApiKey>();

	constructor(options: MemoryApiKeyStoreOptions = {}) {
		for (const record of normalizeApiKeyRecords(options.keys ?? [])) {
			this.keys.set(record.secret, toStoredApiKey(record));
		}
	}

	public async get(secret: string): Promise<StoredApiKey | null> {
		const key = this.keys.get(secret);
		return key ? this.clone(key) : null;
	}

	public async list(): Promise<StoredApiKey[]> {
		return [...this.keys.values()].map((key) => this.clone(key));
	}

	public async close(): Promise<void> {
		return;
	}

	private clone(key: StoredApiKey): StoredApiKey {
		return {
			...key,
			meta: key.meta ? { ...key.meta } : undefined
		};
	}
}
