import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

import { assertTokenLookupField, hasTokenDeleteField, TokenStore } from './base.js';

import type { Token } from './types.js';

/** Private, atomic session persistence for a single server process. */
export class JsonTokenStore extends TokenStore {
	private readonly file: string;
	private readonly lock: string;
	constructor(file: string) {
		super();
		this.file = path.resolve(file);
		this.lock = this.file + '.lock';
		fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
		const directory = fs.lstatSync(path.dirname(this.file));
		if (
			!directory.isDirectory() ||
			directory.isSymbolicLink() ||
			(process.platform !== 'win32' && ((directory.mode & 0o077) !== 0 || directory.uid !== process.getuid?.()))
		) {
			throw new Error('Session directory must be private and owned by the service account');
		}
		this.read();
	}
	private read(): Token[] {
		try {
			const stat = fs.lstatSync(this.file);
			if (
				!stat.isFile() ||
				stat.isSymbolicLink() ||
				(process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()))
			) {
				throw new Error('Session file must be private and owned by the service account');
			}
			const raw: unknown = JSON.parse(fs.readFileSync(this.file, 'utf8'));
			if (!Array.isArray(raw)) throw new Error('Invalid session file');
			return raw.map((item: unknown) => {
				if (!item || typeof item !== 'object') throw new Error('Invalid session record');
				return this.normalizeToken(item as Token);
			});
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
			throw error;
		}
	}
	private matches(record: Token, query: Partial<Token>): boolean {
		return Object.entries(query).every(
			([key, value]) =>
				value === undefined ||
				(key === 'userId' ? record.userId === String(value) : record[key as keyof Token] === value)
		);
	}
	private change<T>(handler: (records: Token[]) => T): T {
		const descriptor = fs.openSync(this.lock, 'wx', 0o600);
		const temporary = this.file + '.' + randomUUID() + '.tmp';
		try {
			const records = this.read();
			const result = handler(records);
			fs.writeFileSync(temporary, JSON.stringify(records), { mode: 0o600, flag: 'wx' });
			fs.renameSync(temporary, this.file);
			return result;
		} finally {
			fs.rmSync(temporary, { force: true });
			fs.closeSync(descriptor);
			fs.unlinkSync(this.lock);
		}
	}
	public override async save(record: Token): Promise<void> {
		const normalized = this.normalizeToken(record);
		this.change((records) => {
			const index = records.findIndex((item) => item.refreshToken === normalized.refreshToken);
			if (index >= 0) records[index] = normalized;
			else records.push(normalized);
		});
	}
	public override async get(query: Partial<Token>, options?: { includeExpired?: boolean }): Promise<Token | null> {
		assertTokenLookupField(query);
		return (
			this.read().find(
				(record) =>
					this.matches(record, query) &&
					(options?.includeExpired || (record.status !== 'revoked' && record.expires!.getTime() > Date.now()))
			) ?? null
		);
	}
	public override async delete(query: Partial<Token>): Promise<number> {
		if (!hasTokenDeleteField(query)) return 0;
		return this.change((records) => {
			const kept = records.filter((record) => !this.matches(record, query));
			const count = records.length - kept.length;
			records.splice(0, records.length, ...kept);
			return count;
		});
	}
	public override async update(updates: Partial<Token> & { refreshToken: string }): Promise<boolean> {
		return this.change((records) => {
			const index = records.findIndex(
				(record) =>
					record.refreshToken === updates.refreshToken &&
					(updates.clientId === undefined || updates.clientId === record.clientId)
			);
			if (index < 0) return false;
			records[index] = this.normalizeToken({ ...records[index], ...updates });
			return true;
		});
	}
	public override async list(
		userId: string | number,
		options: { limit?: number; offset?: number; includeExpired?: boolean } = {}
	): Promise<Token[]> {
		const records = this.read().filter(
			(record) =>
				record.userId === String(userId) &&
				(options.includeExpired || (record.status !== 'revoked' && record.expires!.getTime() > Date.now()))
		);
		return records.slice(options.offset ?? 0, (options.offset ?? 0) + (options.limit ?? records.length));
	}
	public override async close(): Promise<void> {}
}
