import type { AuthIdentifier } from './types.js';

export function normalizeComparableUserId(identifier: AuthIdentifier): string {
	if (typeof identifier === 'number' && Number.isFinite(identifier)) {
		return String(identifier);
	}
	if (typeof identifier === 'string') {
		const trimmed = identifier.trim();
		if (trimmed.length === 0) {
			throw new Error(`Unable to normalise user identifier: ${identifier}`);
		}
		if (/^\d+$/.test(trimmed)) {
			const num = Number(trimmed);
			// Avoid precision loss for large numeric strings
			if (!Number.isSafeInteger(num)) {
				return trimmed;
			}
			return String(num);
		}
		return trimmed;
	}
	throw new Error(`Unable to normalise user identifier: ${identifier}`);
}

export function normalizeNumericUserId(identifier: AuthIdentifier): number {
	const normalized = normalizeComparableUserId(identifier);
	if (/^\d+$/.test(normalized)) {
		const num = Number(normalized);
		if (!Number.isSafeInteger(num)) {
			throw new Error(
				`Sequelize OAuth/Passkey store requires numeric user IDs within safe integer range: ${identifier}`
			);
		}
		return num;
	}
	throw new Error(`Sequelize OAuth/Passkey store requires numeric user IDs: ${identifier}`);
}

export function normalizeStringUserId(identifier: AuthIdentifier): string {
	return normalizeComparableUserId(identifier);
}

export function toOptionalStringId(value: AuthIdentifier | undefined | null): string | undefined {
	if (value === undefined || value === null) {
		return undefined;
	}
	return String(value);
}
