import { createRequire } from 'node:module';

import { Sequelize } from 'sequelize';
import { afterAll, afterEach, beforeEach, describe } from 'vitest';

export interface SequelizeTarget {
	label: string;
	dialect: 'sqlite' | 'mysql' | 'postgres';
	create: () => Promise<Sequelize>;
}

const require = createRequire(import.meta.url);

const CONNECTION_TIMEOUT_MS = 2000;
const preparedUris = new Set<string>();

function hasDriver(pkg: string): boolean {
	try {
		require(pkg);
		return true;
	} catch {
		return false;
	}
}

function buildDialectOptions(dialect: string): Record<string, unknown> | undefined {
	switch (dialect) {
		case 'mysql':
			return { connectTimeout: CONNECTION_TIMEOUT_MS };
		case 'postgres':
			return { connectionTimeoutMillis: CONNECTION_TIMEOUT_MS };
		default:
			return undefined;
	}
}

function buildConnectionOptions(uri: string): {
	logging: false;
	dialectOptions?: Record<string, unknown>;
} {
	const dialect = new URL(uri).protocol.replace(':', '');
	const dialectOptions = buildDialectOptions(dialect);
	return dialectOptions ? { logging: false, dialectOptions } : { logging: false };
}

async function ensureDatabase(uri: string): Promise<void> {
	if (preparedUris.has(uri)) {
		return;
	}
	preparedUris.add(uri);
	const url = new URL(uri);
	const dbName = url.pathname.replace(/^\//, '') || undefined;
	if (!dbName) {
		return; // sqlite or unspecified DB
	}
	const dialect = url.protocol.replace(':', '');
	const dialectOptions = buildDialectOptions(dialect);
	switch (dialect) {
		case 'mysql': {
			try {
				const sequelize = new Sequelize('', url.username || undefined, url.password || undefined, {
					dialect: 'mysql',
					host: url.hostname,
					port: url.port ? Number(url.port) : 3306,
					logging: false,
					dialectOptions
				});
				await sequelize.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``);
				await sequelize.close();
			} catch (error) {
				console.warn(`Unable to create MySQL database ${dbName}: ${(error as Error).message}`);
			}
			return;
		}
		case 'postgres': {
			try {
				const sequelize = new Sequelize('postgres', url.username || undefined, url.password ?? '', {
					dialect: 'postgres',
					host: url.hostname,
					port: url.port ? Number(url.port) : 5432,
					logging: false,
					dialectOptions
				});
				await sequelize.query(`CREATE DATABASE "${dbName}"`);
				await sequelize.close();
			} catch (error) {
				console.warn(`Unable to create Postgres database ${dbName}: ${(error as Error).message}`);
			}
			return;
		}
		default:
			return;
	}
}

async function canConnect(uri: string): Promise<boolean> {
	const options = buildConnectionOptions(uri);
	try {
		const sequelize = new Sequelize(uri, options);
		await sequelize.authenticate();
		await sequelize.close();
		return true;
	} catch (initialError) {
		try {
			await ensureDatabase(uri);
			const sequelize = new Sequelize(uri, options);
			await sequelize.authenticate();
			await sequelize.close();
			return true;
		} catch (error) {
			console.warn(`Skipping ${uri}: ${(initialError as Error).message}`);
			console.warn(`Unable to bootstrap ${uri}: ${(error as Error).message}`);
			return false;
		}
	}
}

/**
 * Dialects the current environment promises to provide, from
 * `TEST_REQUIRED_DIALECTS` (comma-separated, e.g. `mysql,postgres`).
 *
 * Only a dialect named here is allowed to fail the run when it cannot be
 * reached. Environments that provide nothing but SQLite simply leave the
 * variable unset and never fail — the canonical CI workflow sets it because it
 * provisions the services, so a green run there really does mean every promised
 * dialect was exercised.
 */
function requiredDialects(): Set<string> {
	const raw = process.env.TEST_REQUIRED_DIALECTS ?? '';
	const names = raw
		.split(',')
		.map((entry) => entry.trim().toLowerCase())
		.filter(Boolean)
		.map((entry) => (entry === 'pg' ? 'postgres' : entry));
	return new Set(names);
}

/**
 * Resolve an optional SQL target.
 *
 * Unreachable targets are skipped with a warning so a machine with only SQLite
 * stays usable. The exception is a dialect listed in `TEST_REQUIRED_DIALECTS`:
 * that is an explicit promise the environment made, so failing to honour it is
 * a hard error rather than a suite that quietly disappears.
 */
async function resolveOptionalTarget(options: {
	kind: string;
	dialect: 'mysql' | 'postgres';
	label: string;
	url: string | undefined;
	skip: string | undefined;
	skipVar: string;
	driver: string;
	urlVar: string;
}): Promise<SequelizeTarget | null> {
	const { kind, dialect, label, url, skip, skipVar, driver, urlVar } = options;
	const required = requiredDialects().has(dialect);

	if (skip || !url) {
		if (required) {
			const cause = skip ? `${skipVar} is set` : `${urlVar} is not set`;
			throw new Error(
				`[sequelize-targets] TEST_REQUIRED_DIALECTS lists "${dialect}" but ${cause}, so "${kind}" would not run against it. ` +
					`Provide ${urlVar}, or drop "${dialect}" from TEST_REQUIRED_DIALECTS.`
			);
		}
		return null;
	}

	const driverMissing = !hasDriver(driver);
	if (!driverMissing && (await canConnect(url))) {
		return {
			label: `${kind} (${label})`,
			dialect,
			create: async () => new Sequelize(url, { logging: false })
		};
	}

	const reason = driverMissing
		? `the "${driver}" driver is not installed`
		: 'the database could not be reached or created';
	if (required) {
		throw new Error(
			`[sequelize-targets] TEST_REQUIRED_DIALECTS lists "${dialect}" for "${kind}" but ${reason}. ` +
				`Refusing to silently skip a promised dialect — fix the service, or drop "${dialect}" from TEST_REQUIRED_DIALECTS.`
		);
	}
	console.warn(`Skipping ${label} target for ${kind}: ${reason}`);
	return null;
}

async function buildTargets(kind: string): Promise<SequelizeTarget[]> {
	const targets: SequelizeTarget[] = [];

	if (!process.env.TEST_SKIP_SQLITE && hasDriver('sqlite3')) {
		targets.push({
			label: `${kind} (sqlite)`,
			dialect: 'sqlite',
			create: async () =>
				new Sequelize({
					dialect: 'sqlite',
					storage: ':memory:',
					logging: false
				})
		});
	}

	const mysql = await resolveOptionalTarget({
		kind,
		dialect: 'mysql',
		label: 'mysql',
		url: process.env.TEST_MYSQL_URL,
		skip: process.env.TEST_SKIP_MYSQL,
		skipVar: 'TEST_SKIP_MYSQL',
		driver: 'mysql2',
		urlVar: 'TEST_MYSQL_URL'
	});
	if (mysql) {
		targets.push(mysql);
	}

	const postgres = await resolveOptionalTarget({
		kind,
		dialect: 'postgres',
		label: 'postgres',
		url: process.env.TEST_PG_URL,
		skip: process.env.TEST_SKIP_PG,
		skipVar: 'TEST_SKIP_PG',
		driver: 'pg',
		urlVar: 'TEST_PG_URL'
	});
	if (postgres) {
		targets.push(postgres);
	}

	return targets;
}

function extractTableName(entry: unknown): string | null {
	if (typeof entry === 'string') {
		return entry;
	}
	if (!entry || typeof entry !== 'object') {
		return null;
	}
	const record = entry as {
		tableName?: unknown;
		name?: unknown;
		table_name?: unknown;
	};
	if (typeof record.tableName === 'string' && record.tableName.length > 0) {
		return record.tableName;
	}
	if (typeof record.name === 'string' && record.name.length > 0) {
		return record.name;
	}
	if (typeof record.table_name === 'string' && record.table_name.length > 0) {
		return record.table_name;
	}
	return null;
}

export async function listSequelizeTables(sequelize: Sequelize): Promise<string[]> {
	const tables = await sequelize.getQueryInterface().showAllTables();
	if (!Array.isArray(tables)) {
		return [];
	}
	return tables.map(extractTableName).filter((name): name is string => !!name);
}

export class SequelizeTestHarness {
	private readonly created = new Set<Sequelize>();

	constructor(private readonly kind: string) {}

	public async getTargets(): Promise<SequelizeTarget[]> {
		return buildTargets(this.kind);
	}

	public async setup(target: SequelizeTarget): Promise<Sequelize> {
		const sequelize = await target.create();
		this.created.add(sequelize);
		return sequelize;
	}

	public async teardown(target?: Sequelize | null): Promise<void> {
		if (!target) {
			return;
		}
		try {
			await target.close();
		} finally {
			this.created.delete(target);
		}
	}

	public async teardownAll(): Promise<void> {
		for (const sequelize of [...this.created]) {
			await this.teardown(sequelize);
		}
	}
}

export async function getSequelizeTargets(kind: string): Promise<SequelizeTarget[]> {
	return buildTargets(kind);
}

export interface SequelizeSuiteOptions {
	filterTargets?: (target: SequelizeTarget) => boolean;
}

export async function describeSequelizeSuite(
	kind: string,
	define: (ctx: { target: SequelizeTarget; getSequelize: () => Sequelize }) => void,
	options: SequelizeSuiteOptions = {}
): Promise<void> {
	const harness = new SequelizeTestHarness(kind);
	const allTargets = await harness.getTargets();
	const targets = options.filterTargets ? allTargets.filter(options.filterTargets) : allTargets;

	if (targets.length === 0) {
		describe.skip(`${kind} (no database targets)`, () => {});
		return;
	}

	for (const target of targets) {
		describe(target.label, () => {
			let sequelize: Sequelize | null = null;

			beforeEach(async () => {
				sequelize = await harness.setup(target);
			});

			afterEach(async () => {
				await harness.teardown(sequelize);
				sequelize = null;
			});

			define({
				target,
				getSequelize: () => {
					if (!sequelize) {
						throw new Error('Sequelize instance is not initialised for this test');
					}
					return sequelize;
				}
			});
		});
	}

	afterAll(async () => {
		await harness.teardownAll();
	});
}
