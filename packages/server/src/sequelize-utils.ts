import { DataTypes, type InitOptions, type Model, type Sequelize } from 'sequelize';

export const DIALECTS_SUPPORTING_UNSIGNED = new Set(['mysql', 'mariadb']);

export function integerIdType(sequelize: Sequelize) {
	return DIALECTS_SUPPORTING_UNSIGNED.has(sequelize.getDialect()) ? DataTypes.INTEGER.UNSIGNED : DataTypes.INTEGER;
}

export function tableOptions<ModelType extends Model>(
	sequelize: Sequelize,
	tableName: string,
	tablePrefix?: string,
	extra?: Partial<InitOptions<ModelType>>
): InitOptions<ModelType> {
	const opts: InitOptions<ModelType> = {
		sequelize,
		tableName: applyTablePrefix(tablePrefix, tableName)
	};
	if (extra) {
		Object.assign(opts, extra);
	}
	if (DIALECTS_SUPPORTING_UNSIGNED.has(sequelize.getDialect())) {
		opts.charset = 'utf8mb4';
		opts.collate = 'utf8mb4_unicode_ci';
	}
	return opts;
}

export function normalizeTablePrefix(prefix?: string): string | undefined {
	if (!prefix) {
		return undefined;
	}
	const trimmed = prefix.trim();
	return trimmed.length > 0 ? trimmed : undefined;
}

export function applyTablePrefix(prefix: string | undefined, tableName: string): string {
	const normalized = normalizeTablePrefix(prefix);
	return normalized ? `${normalized}${tableName}` : tableName;
}

export function encodeStringArray(values: string[] | undefined): string {
	return JSON.stringify(values ?? []);
}

export function decodeStringArray(raw: string | null | undefined): string[] {
	if (!raw) {
		return [];
	}
	try {
		const parsed = JSON.parse(raw);
		if (Array.isArray(parsed)) {
			return parsed.filter((entry) => typeof entry === 'string' && entry.length > 0);
		}
	} catch {
		// Malformed JSON — return empty rather than guessing via whitespace split.
		// A whitespace-split fallback could silently grant unintended permissions
		// if a scope/role column contains a corrupted value like "admin user".
	}
	return [];
}
