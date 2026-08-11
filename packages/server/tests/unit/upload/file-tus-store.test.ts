import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { FileTusUploadStore } from '../../../src/upload/file';
import { TusUploadExceedsLengthError, TusUploadOffsetError } from '../../../src/upload/memory';

describe('FileTusUploadStore', () => {
	const tempDirs: string[] = [];

	afterEach(() => {
		for (const dir of tempDirs.splice(0)) {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	function createStoragePath(): string {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-file-store-'));
		tempDirs.push(root);
		return path.join(root, 'tus');
	}

	it('persists uploads across store instances and enforces append offsets and lengths', async () => {
		const storagePath = createStoragePath();
		const firstStore = new FileTusUploadStore(storagePath);
		const created = await firstStore.createUpload({
			id: 'persistent-upload',
			length: 5,
			metadata: { filename: 'video.mp4' },
			userId: 'user-1'
		});

		expect(created.filepath).toBe(path.join(storagePath, 'persistent-upload.upload'));
		expect(fs.statSync(created.filepath!).mode & 0o777).toBe(0o600);
		expect(fs.statSync(path.join(storagePath, 'persistent-upload.json')).mode & 0o777).toBe(0o600);

		await firstStore.appendUpload({
			uploadId: created.id,
			offset: 0,
			chunk: Buffer.from('ab')
		});

		const reopenedStore = new FileTusUploadStore(storagePath);
		const reopened = await reopenedStore.getUpload(created.id);
		expect(reopened).toMatchObject({
			id: created.id,
			length: 5,
			offset: 2,
			metadata: { filename: 'video.mp4' },
			userId: 'user-1'
		});
		expect(reopened?.createdAt).toBeInstanceOf(Date);
		expect(reopened?.updatedAt).toBeInstanceOf(Date);

		const wrongOffset = reopenedStore.appendUpload({
			uploadId: created.id,
			offset: 0,
			chunk: Buffer.from('x')
		});
		await expect(wrongOffset).rejects.toBeInstanceOf(TusUploadOffsetError);
		await expect(wrongOffset).rejects.toMatchObject({ currentOffset: 2 });
		await expect(
			reopenedStore.appendUpload({
				uploadId: created.id,
				offset: 2,
				chunk: Buffer.from('toolong')
			})
		).rejects.toBeInstanceOf(TusUploadExceedsLengthError);

		const completed = await reopenedStore.appendUpload({
			uploadId: created.id,
			offset: 2,
			chunk: Buffer.from('cde')
		});
		expect(completed.offset).toBe(5);
		expect(completed.completedAt).toBeInstanceOf(Date);
		expect(fs.readFileSync(completed.filepath!, 'utf8')).toBe('abcde');

		expect(await reopenedStore.deleteUpload(created.id)).toBe(true);
		expect(await reopenedStore.deleteUpload(created.id)).toBe(false);
		expect(fs.existsSync(path.join(storagePath, 'persistent-upload.upload'))).toBe(false);
		expect(fs.existsSync(path.join(storagePath, 'persistent-upload.json'))).toBe(false);
	});

	it('recovers the stored offset when data reached disk before metadata was updated', async () => {
		const storagePath = createStoragePath();
		const firstStore = new FileTusUploadStore(storagePath);
		const created = await firstStore.createUpload({
			id: 'recovered-upload',
			length: 5,
			metadata: {}
		});
		await firstStore.appendUpload({
			uploadId: created.id,
			offset: 0,
			chunk: Buffer.from('ab')
		});
		fs.appendFileSync(created.filepath!, Buffer.from('cde'));

		const reopenedStore = new FileTusUploadStore(storagePath);
		const recovered = await reopenedStore.getUpload(created.id);
		const storedMetadata = JSON.parse(
			fs.readFileSync(path.join(storagePath, 'recovered-upload.json'), 'utf8')
		) as Record<string, unknown>;

		expect(recovered?.offset).toBe(5);
		expect(recovered?.completedAt).toBeInstanceOf(Date);
		expect(storedMetadata.offset).toBe(5);
		expect(storedMetadata.completedAt).toBeTruthy();
	});

	it('purges incomplete, corrupt, temporary, and metadata-free stale files but preserves completed data', async () => {
		const storagePath = createStoragePath();
		const store = new FileTusUploadStore(storagePath);
		const incomplete = await store.createUpload({ id: 'incomplete', length: 5, metadata: {} });
		await store.appendUpload({
			uploadId: incomplete.id,
			offset: 0,
			chunk: Buffer.from('ab')
		});
		const completed = await store.createUpload({ id: 'completed', length: 1, metadata: {} });
		await store.appendUpload({
			uploadId: completed.id,
			offset: 0,
			chunk: Buffer.from('x')
		});

		const staleOrphanPath = path.join(storagePath, 'orphan.upload');
		const freshOrphanPath = path.join(storagePath, 'fresh.upload');
		const corruptDataPath = path.join(storagePath, 'corrupt.upload');
		const corruptMetadataPath = path.join(storagePath, 'corrupt.json');
		const temporaryPath = path.join(storagePath, 'metadata.json.partial.tmp');
		fs.writeFileSync(staleOrphanPath, Buffer.from('old'));
		fs.writeFileSync(freshOrphanPath, Buffer.from('fresh'));
		fs.writeFileSync(corruptDataPath, Buffer.from('oops'));
		fs.writeFileSync(corruptMetadataPath, '{not-json');
		fs.writeFileSync(temporaryPath, 'temporary');

		const cutoff = new Date(Date.now() + 1_000);
		const future = new Date(cutoff.getTime() + 60_000);
		fs.utimesSync(freshOrphanPath, future, future);

		const result = await store.purgeExpired(cutoff);

		expect(result).toEqual({ uploads: 3, bytes: 9 });
		expect(await store.getUpload(incomplete.id)).toBeNull();
		expect(await store.getUpload(completed.id)).not.toBeNull();
		expect(fs.existsSync(staleOrphanPath)).toBe(false);
		expect(fs.existsSync(freshOrphanPath)).toBe(true);
		expect(fs.existsSync(corruptDataPath)).toBe(false);
		expect(fs.existsSync(corruptMetadataPath)).toBe(false);
		expect(fs.existsSync(temporaryPath)).toBe(false);
	});

	it('rejects unsafe and duplicate upload IDs', async () => {
		expect(() => new FileTusUploadStore(' ')).toThrow(/requires a storage path/);
		const store = new FileTusUploadStore(createStoragePath());
		await expect(store.createUpload({ id: '../unsafe', length: 1, metadata: {} })).rejects.toThrow(
			'Invalid upload ID'
		);
		await store.createUpload({ id: 'duplicate', length: 1, metadata: {} });
		await expect(store.createUpload({ id: 'duplicate', length: 1, metadata: {} })).rejects.toMatchObject({
			code: 'EEXIST'
		});
	});
});
