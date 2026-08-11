import { randomUUID } from 'node:crypto';
import { mkdir, open, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { removeStaleUploadFile } from './cleanup.js';
import { cloneTusUploadRecord, nextTusUploadOffset } from './record.js';

import type {
	TusAppendInput,
	TusCreateUploadInput,
	TusUploadRecord,
	TusUploadStore,
	UploadPurgeResult
} from './types.js';
import type { Dirent } from 'node:fs';

type StoredTusUploadRecord = Omit<TusUploadRecord, 'createdAt' | 'updatedAt' | 'completedAt' | 'filepath'> & {
	createdAt: string;
	updatedAt: string;
	completedAt?: string;
};

function isSafeUploadId(uploadId: string): boolean {
	return /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(uploadId) && uploadId !== '.' && uploadId !== '..';
}

function isValidStoredRecord(stored: StoredTusUploadRecord, uploadId: string): boolean {
	return (
		stored.id === uploadId &&
		Number.isSafeInteger(stored.length) &&
		Number.isSafeInteger(stored.offset) &&
		stored.length >= 0 &&
		stored.offset >= 0 &&
		stored.offset <= stored.length &&
		typeof stored.metadata === 'object' &&
		stored.metadata !== null &&
		!Array.isArray(stored.metadata)
	);
}

/** Persistent TUS store backed by one data file and one JSON metadata file per upload. */
export class FileTusUploadStore implements TusUploadStore {
	public readonly storagePath: string;
	private readonly activeUploads = new Set<string>();
	private readonly locks = new Map<string, Promise<void>>();

	constructor(storagePath: string) {
		const configured = storagePath.trim();
		if (!configured) {
			throw new Error('FileTusUploadStore requires a storage path');
		}
		this.storagePath = path.resolve(configured);
	}

	public async createUpload(input: TusCreateUploadInput): Promise<TusUploadRecord> {
		const id = input.id?.trim() || randomUUID();
		this.assertUploadId(id);
		return this.withLock(id, async () => {
			await mkdir(this.storagePath, { recursive: true, mode: 0o700 });
			const now = new Date();
			const record: TusUploadRecord = {
				id,
				length: Math.max(0, Math.floor(input.length)),
				offset: 0,
				metadata: { ...input.metadata },
				...(input.userId ? { userId: input.userId } : {}),
				filepath: this.dataPath(id),
				createdAt: now,
				updatedAt: now
			};
			const handle = await open(record.filepath!, 'wx', 0o600);
			await handle.close();
			try {
				await this.writeRecord(record, true);
			} catch (error) {
				await rm(record.filepath!, { force: true }).catch(() => undefined);
				throw error;
			}
			return cloneTusUploadRecord(record);
		});
	}

	public async getUpload(uploadId: string): Promise<TusUploadRecord | null> {
		this.assertUploadId(uploadId);
		return this.withLock(uploadId, async () => this.readRecord(uploadId));
	}

	public async appendUpload(input: TusAppendInput): Promise<TusUploadRecord> {
		this.assertUploadId(input.uploadId);
		return this.withLock(input.uploadId, async () => {
			const current = await this.readRecord(input.uploadId);
			if (!current) {
				throw new Error('Upload not found');
			}
			const nextOffset = nextTusUploadOffset(current, input);

			this.activeUploads.add(input.uploadId);
			try {
				const handle = await open(current.filepath!, 'r+');
				try {
					let written = 0;
					while (written < input.chunk.length) {
						const result = await handle.write(
							input.chunk,
							written,
							input.chunk.length - written,
							current.offset + written
						);
						if (result.bytesWritten === 0) {
							throw new Error('Unable to write upload chunk');
						}
						written += result.bytesWritten;
					}
				} finally {
					await handle.close();
				}

				const now = new Date();
				const updated: TusUploadRecord = {
					...current,
					offset: nextOffset,
					updatedAt: now,
					...(nextOffset === current.length ? { completedAt: now } : {})
				};
				await this.writeRecord(updated);
				return cloneTusUploadRecord(updated);
			} finally {
				this.activeUploads.delete(input.uploadId);
			}
		});
	}

	public async deleteUpload(uploadId: string): Promise<boolean> {
		this.assertUploadId(uploadId);
		return this.withLock(uploadId, async () => {
			const record = await this.readRecord(uploadId);
			if (!record) {
				return false;
			}
			await this.removeUploadFiles(uploadId);
			return true;
		});
	}

	public async purgeExpired(cutoff: Date): Promise<UploadPurgeResult> {
		await mkdir(this.storagePath, { recursive: true, mode: 0o700 });
		const result: UploadPurgeResult = { uploads: 0, bytes: 0 };
		const entries = await readdir(this.storagePath, { withFileTypes: true });
		const metadataIds = await this.purgeMetadataEntries(entries, cutoff, result);
		await this.purgeLooseEntries(entries, cutoff, metadataIds, result);
		return result;
	}

	private async purgeMetadataEntries(
		entries: Dirent[],
		cutoff: Date,
		result: UploadPurgeResult
	): Promise<Set<string>> {
		const metadataIds = new Set<string>();
		for (const entry of entries) {
			if (!entry.isFile() || !entry.name.endsWith('.json')) {
				continue;
			}
			const uploadId = entry.name.slice(0, -'.json'.length);
			if (!isSafeUploadId(uploadId) || this.activeUploads.has(uploadId)) {
				continue;
			}
			metadataIds.add(uploadId);
			await this.purgeMetadataUpload(uploadId, cutoff, metadataIds, result);
		}
		return metadataIds;
	}

	private async purgeLooseEntries(
		entries: Dirent[],
		cutoff: Date,
		metadataIds: Set<string>,
		result: UploadPurgeResult
	): Promise<void> {
		for (const entry of entries) {
			if (!entry.isFile()) {
				continue;
			}
			await this.purgeLooseEntry(entry.name, cutoff, metadataIds, result);
		}
	}

	private async purgeLooseEntry(
		filename: string,
		cutoff: Date,
		metadataIds: Set<string>,
		result: UploadPurgeResult
	): Promise<void> {
		if (filename.endsWith('.tmp')) {
			await removeStaleUploadFile(path.join(this.storagePath, filename), cutoff);
			return;
		}
		if (!filename.endsWith('.upload')) {
			return;
		}
		const uploadId = filename.slice(0, -'.upload'.length);
		if (!isSafeUploadId(uploadId) || metadataIds.has(uploadId) || this.activeUploads.has(uploadId)) {
			return;
		}
		const removedBytes = await removeStaleUploadFile(this.dataPath(uploadId), cutoff);
		if (removedBytes !== null) {
			result.uploads += 1;
			result.bytes += removedBytes;
		}
	}

	private async purgeMetadataUpload(
		uploadId: string,
		cutoff: Date,
		metadataIds: Set<string>,
		result: UploadPurgeResult
	): Promise<void> {
		await this.withLock(uploadId, async () => {
			let record: TusUploadRecord | null;
			try {
				record = await this.readRecord(uploadId);
			} catch {
				await this.purgeInvalidMetadata(uploadId, cutoff, metadataIds, result);
				return;
			}
			if (!record || record.completedAt || record.updatedAt >= cutoff) {
				return;
			}
			const removedBytes = await this.removeUploadFiles(uploadId);
			result.uploads += 1;
			result.bytes += removedBytes ?? record.offset;
		});
	}

	private async purgeInvalidMetadata(
		uploadId: string,
		cutoff: Date,
		metadataIds: Set<string>,
		result: UploadPurgeResult
	): Promise<void> {
		const metadataStats = await stat(this.recordPath(uploadId)).catch(() => null);
		if (!metadataStats || metadataStats.mtime >= cutoff) {
			return;
		}
		const removedBytes = await this.removeUploadFiles(uploadId);
		metadataIds.delete(uploadId);
		if (removedBytes !== null) {
			result.uploads += 1;
			result.bytes += removedBytes;
		}
	}

	private async removeUploadFiles(uploadId: string): Promise<number | null> {
		const fileStats = await stat(this.dataPath(uploadId)).catch(() => null);
		await Promise.all([
			rm(this.dataPath(uploadId), { force: true }),
			rm(this.recordPath(uploadId), { force: true })
		]);
		return fileStats?.size ?? null;
	}

	private assertUploadId(uploadId: string): void {
		if (!isSafeUploadId(uploadId)) {
			throw new Error('Invalid upload ID');
		}
	}

	private dataPath(uploadId: string): string {
		return path.join(this.storagePath, `${uploadId}.upload`);
	}

	private recordPath(uploadId: string): string {
		return path.join(this.storagePath, `${uploadId}.json`);
	}

	private async readRecord(uploadId: string): Promise<TusUploadRecord | null> {
		const stored = await this.readStoredRecord(uploadId);
		if (!stored) {
			return null;
		}
		const record = this.deserializeRecord(uploadId, stored);
		await this.reconcileFileOffset(record);
		return record;
	}

	private async readStoredRecord(uploadId: string): Promise<StoredTusUploadRecord | null> {
		let stored: StoredTusUploadRecord;
		try {
			stored = JSON.parse(await readFile(this.recordPath(uploadId), 'utf8')) as StoredTusUploadRecord;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
				return null;
			}
			throw error;
		}
		if (!isValidStoredRecord(stored, uploadId)) {
			throw new Error(`Stored upload ${uploadId} has invalid metadata`);
		}
		return stored;
	}

	private deserializeRecord(uploadId: string, stored: StoredTusUploadRecord): TusUploadRecord {
		const { createdAt, updatedAt, completedAt, ...storedRecord } = stored;
		const createdDate = new Date(createdAt);
		const updatedDate = new Date(updatedAt);
		const completedDate = completedAt ? new Date(completedAt) : undefined;
		if (
			Number.isNaN(createdDate.getTime()) ||
			Number.isNaN(updatedDate.getTime()) ||
			(completedDate && Number.isNaN(completedDate.getTime()))
		) {
			throw new Error(`Stored upload ${uploadId} has invalid timestamps`);
		}
		const filepath = this.dataPath(uploadId);
		return {
			...storedRecord,
			metadata: { ...stored.metadata },
			filepath,
			createdAt: createdDate,
			updatedAt: updatedDate,
			...(completedDate ? { completedAt: completedDate } : {})
		};
	}

	private async reconcileFileOffset(record: TusUploadRecord): Promise<void> {
		const filepath = this.dataPath(record.id);
		const fileStats = await stat(filepath);
		if (fileStats.size === record.offset) {
			return;
		}
		if (fileStats.size > record.length) {
			throw new Error(`Stored upload ${record.id} exceeds its declared length`);
		}
		const now = new Date();
		record.offset = fileStats.size;
		record.updatedAt = now;
		if (record.offset === record.length) {
			record.completedAt = record.completedAt ?? now;
		}
		await this.writeRecord(record);
	}

	private async writeRecord(record: TusUploadRecord, create = false): Promise<void> {
		const stored: StoredTusUploadRecord = {
			id: record.id,
			length: record.length,
			offset: record.offset,
			metadata: { ...record.metadata },
			...(record.userId ? { userId: record.userId } : {}),
			createdAt: record.createdAt.toISOString(),
			updatedAt: record.updatedAt.toISOString(),
			...(record.completedAt ? { completedAt: record.completedAt.toISOString() } : {})
		};
		const destination = this.recordPath(record.id);
		if (create) {
			await writeFile(destination, JSON.stringify(stored), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
			return;
		}
		const temporary = `${destination}.${randomUUID()}.tmp`;
		try {
			await writeFile(temporary, JSON.stringify(stored), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
			await rename(temporary, destination);
		} finally {
			await rm(temporary, { force: true }).catch(() => undefined);
		}
	}

	private async withLock<T>(uploadId: string, action: () => Promise<T>): Promise<T> {
		const previous = this.locks.get(uploadId) ?? Promise.resolve();
		let release!: () => void;
		const current = new Promise<void>((resolve) => {
			release = resolve;
		});
		const queued = previous.then(() => current);
		this.locks.set(uploadId, queued);
		await previous;
		try {
			return await action();
		} finally {
			release();
			if (this.locks.get(uploadId) === queued) {
				this.locks.delete(uploadId);
			}
		}
	}
}
