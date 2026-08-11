export type TusMetadata = Record<string, string>;

export interface TusUploadRecord {
	id: string;
	length: number;
	offset: number;
	metadata: TusMetadata;
	userId?: string;
	/** Absolute path to the stored upload when the store is file-backed. */
	filepath?: string;
	createdAt: Date;
	updatedAt: Date;
	completedAt?: Date;
}

export interface TusCreateUploadInput {
	id?: string;
	length: number;
	metadata: TusMetadata;
	userId?: string;
}

export interface TusAppendInput {
	uploadId: string;
	offset: number;
	chunk: Buffer;
}

export interface UploadPurgeResult {
	uploads: number;
	bytes: number;
}

export interface TusUploadStore {
	/** Storage directory used by disk-space checks, when the store is file-backed. */
	readonly storagePath?: string;
	createUpload(input: TusCreateUploadInput): Promise<TusUploadRecord>;
	getUpload(uploadId: string): Promise<TusUploadRecord | null>;
	appendUpload(input: TusAppendInput): Promise<TusUploadRecord>;
	deleteUpload?(uploadId: string): Promise<boolean>;
	/** Remove incomplete uploads last updated before the supplied cutoff. */
	purgeExpired?(cutoff: Date): Promise<UploadPurgeResult>;
}
