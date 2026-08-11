import { readFileSync } from 'node:fs';
import { readFile as readFileAsync } from 'node:fs/promises';

import { normalizeApiKeyFile, toStoredApiKey } from './base.js';

import type { ApiKeyStore, StoredApiKey } from './types.js';

export interface JsonApiKeyStoreOptions {
	file: string;
	reload?: boolean;
}

export class JsonApiKeyStore implements ApiKeyStore {
	private readonly file: string;
	private readonly reload: boolean;
	private keys: Map<string, StoredApiKey> | null = null;

	constructor(options: JsonApiKeyStoreOptions) {
		if (!options?.file || options.file.trim().length === 0) {
			throw new Error('JsonApiKeyStore requires a file path');
		}
		this.file = options.file;
		this.reload = options.reload ?? false;
		this.keys = this.parse(readFileSync(this.file, 'utf8'));
	}

	public async get(secret: string): Promise<StoredApiKey | null> {
		const keys = await this.load();
		const key = keys.get(secret);
		return key ? this.clone(key) : null;
	}

	public async list(): Promise<StoredApiKey[]> {
		const keys = await this.load();
		return [...keys.values()].map((key) => this.clone(key));
	}

	public async close(): Promise<void> {
		this.keys = null;
	}

	private async load(): Promise<Map<string, StoredApiKey>> {
		if (this.keys && !this.reload) {
			return this.keys;
		}
		const raw = await readFileAsync(this.file, 'utf8');
		this.keys = this.parse(raw);
		return this.keys;
	}

	private parse(raw: string): Map<string, StoredApiKey> {
		const parsed = JSON.parse(raw) as unknown;
		const file = normalizeApiKeyFile(parsed);
		const keys = new Map<string, StoredApiKey>();
		for (const record of file.keys) {
			keys.set(record.secret, toStoredApiKey(record));
		}
		return keys;
	}

	private clone(key: StoredApiKey): StoredApiKey {
		return {
			...key,
			meta: key.meta ? { ...key.meta } : undefined
		};
	}
}
