import { randomUUID } from 'node:crypto';

import { TusUploadCapacityError } from './errors.js';
import { cloneTusUploadRecord, nextTusUploadOffset } from './record.js';

import type { TusAppendInput, TusCreateUploadInput, TusUploadRecord, TusUploadStore } from './types.js';

export { TusUploadCapacityError, TusUploadExceedsLengthError, TusUploadOffsetError } from './errors.js';

export interface MemoryTusUploadStoreOptions {
	/** Maximum total declared size retained by the store. Defaults to 30 MiB. */
	maxBytes?: number;
	/** Maximum number of uploads retained by the store. Defaults to 100. */
	maxUploads?: number;
}

export class MemoryTusUploadStore implements TusUploadStore {
	private readonly uploads = new Map<string, TusUploadRecord>();
	private readonly chunks = new Map<string, Buffer[]>();
	private readonly maxBytes: number;
	private readonly maxUploads: number;
	private reservedBytes = 0;

	constructor(options: MemoryTusUploadStoreOptions = {}) {
		this.maxBytes = options.maxBytes ?? 30 * 1024 * 1024;
		this.maxUploads = options.maxUploads ?? 100;
	}

	public async createUpload(input: TusCreateUploadInput): Promise<TusUploadRecord> {
		const id = input.id?.trim() || randomUUID();
		if (this.uploads.has(id)) {
			throw new Error(`Upload ${id} already exists`);
		}
		const length = Math.max(0, Math.floor(input.length));
		if (this.uploads.size >= this.maxUploads) {
			throw new TusUploadCapacityError(`Memory upload store is limited to ${this.maxUploads} uploads`);
		}
		if (length > this.maxBytes || this.reservedBytes + length > this.maxBytes) {
			throw new TusUploadCapacityError(`Memory upload store is limited to ${this.maxBytes} bytes`);
		}
		const now = new Date();
		const record: TusUploadRecord = {
			id,
			length,
			offset: 0,
			metadata: { ...input.metadata },
			...(input.userId ? { userId: input.userId } : {}),
			createdAt: now,
			updatedAt: now
		};
		this.uploads.set(id, record);
		this.chunks.set(id, []);
		this.reservedBytes += length;
		return cloneTusUploadRecord(record);
	}

	public async getUpload(uploadId: string): Promise<TusUploadRecord | null> {
		const found = this.uploads.get(uploadId);
		return found ? cloneTusUploadRecord(found) : null;
	}

	public async appendUpload(input: TusAppendInput): Promise<TusUploadRecord> {
		const current = this.uploads.get(input.uploadId);
		if (!current) {
			throw new Error('Upload not found');
		}
		const nextOffset = nextTusUploadOffset(current, input);
		const now = new Date();
		const updated: TusUploadRecord = {
			...current,
			offset: nextOffset,
			updatedAt: now,
			...(nextOffset === current.length ? { completedAt: now } : {})
		};
		this.uploads.set(input.uploadId, updated);
		if (input.chunk.length > 0) {
			this.chunks.get(input.uploadId)?.push(Buffer.from(input.chunk));
		}
		return cloneTusUploadRecord(updated);
	}

	public async deleteUpload(uploadId: string): Promise<boolean> {
		const record = this.uploads.get(uploadId);
		this.chunks.delete(uploadId);
		const deleted = this.uploads.delete(uploadId);
		if (deleted && record) {
			this.reservedBytes -= record.length;
		}
		return deleted;
	}

	public async purgeExpired(cutoff: Date): Promise<{ uploads: number; bytes: number }> {
		let uploads = 0;
		let bytes = 0;
		for (const [uploadId, record] of this.uploads) {
			if (record.completedAt || record.updatedAt >= cutoff) {
				continue;
			}
			uploads += 1;
			bytes += record.offset;
			await this.deleteUpload(uploadId);
		}
		return { uploads, bytes };
	}

	public readUpload(uploadId: string): Buffer | null {
		const chunks = this.chunks.get(uploadId);
		if (!chunks) {
			return null;
		}
		return Buffer.concat(chunks);
	}
}
