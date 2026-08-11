import type { ApiKeyFile, ApiKeyRecord, StoredApiKey } from './types.js';
import type { AuthIdentifier } from '../auth-api/types.js';

function isAuthIdentifier(value: unknown): value is AuthIdentifier {
	if (typeof value === 'string') return value.trim().length > 0;
	if (typeof value === 'number') return Number.isFinite(value);
	return false;
}

function normalizeIdentifier(value: AuthIdentifier): AuthIdentifier {
	return typeof value === 'string' ? value.trim() : value;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function normalizeApiKeyRecord(record: unknown, index: number): ApiKeyRecord {
	if (!isPlainObject(record)) {
		throw new Error(`API key record at index ${index} must be an object`);
	}

	const secret = record.secret;
	if (typeof secret !== 'string' || secret.trim().length === 0) {
		throw new Error(`API key record at index ${index} requires a non-empty secret`);
	}
	const uid = record.uid;
	if (!isAuthIdentifier(uid)) {
		throw new Error(`API key record at index ${index} requires uid as a non-empty string or finite number`);
	}
	const euid = record.euid;
	if (euid !== undefined && !isAuthIdentifier(euid)) {
		throw new Error(`API key record at index ${index} has invalid euid`);
	}
	const id = record.id;
	if (id !== undefined && (typeof id !== 'string' || id.trim().length === 0)) {
		throw new Error(`API key record at index ${index} has invalid id`);
	}
	const meta = record.meta;
	if (meta !== undefined && !isPlainObject(meta)) {
		throw new Error(`API key record at index ${index} has invalid meta`);
	}

	return {
		secret: secret.trim(),
		uid: normalizeIdentifier(uid),
		...(euid !== undefined ? { euid: normalizeIdentifier(euid) } : {}),
		...(typeof id === 'string' ? { id: id.trim() } : {}),
		...(meta ? { meta: { ...meta } } : {})
	};
}

export function normalizeApiKeyRecords(records: unknown): ApiKeyRecord[] {
	if (!Array.isArray(records)) {
		throw new Error('API key records must be an array');
	}
	const normalized = records.map((record, index) => normalizeApiKeyRecord(record, index));
	const seenSecrets = new Set<string>();
	const seenIds = new Set<string>();
	for (const record of normalized) {
		if (seenSecrets.has(record.secret)) {
			throw new Error(`Duplicate API key secret${record.id ? ` for ${record.id}` : ''}`);
		}
		seenSecrets.add(record.secret);
		if (record.id) {
			if (seenIds.has(record.id)) {
				throw new Error(`Duplicate API key id: ${record.id}`);
			}
			seenIds.add(record.id);
		}
	}
	return normalized;
}

export function normalizeApiKeyFile(input: unknown): ApiKeyFile {
	if (!isPlainObject(input)) {
		throw new Error('API key file must contain an object');
	}
	if (input.version !== 1) {
		throw new Error('API key file version must be 1');
	}
	return {
		version: 1,
		keys: normalizeApiKeyRecords(input.keys)
	};
}

export function toStoredApiKey(record: ApiKeyRecord): StoredApiKey {
	return {
		uid: record.uid,
		...(record.euid !== undefined ? { euid: record.euid } : {}),
		...(record.id ? { id: record.id } : {}),
		...(record.meta ? { meta: { ...record.meta } } : {})
	};
}
