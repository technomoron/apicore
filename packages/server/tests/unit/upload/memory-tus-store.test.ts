import { afterEach, describe, expect, it, vi } from 'vitest';

import {
	MemoryTusUploadStore,
	TusUploadCapacityError,
	TusUploadExceedsLengthError,
	TusUploadOffsetError
} from '../../../src/upload/memory';

describe('MemoryTusUploadStore', () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it('creates, appends, completes, clones, and deletes uploads', async () => {
		const store = new MemoryTusUploadStore();
		const created = await store.createUpload({
			id: 'memory-upload',
			length: 5,
			metadata: { filename: 'video.mp4' },
			userId: 'user-1'
		});

		created.metadata.filename = 'changed-by-caller';
		expect((await store.getUpload(created.id))?.metadata.filename).toBe('video.mp4');

		const partial = await store.appendUpload({
			uploadId: created.id,
			offset: 0,
			chunk: Buffer.from('ab')
		});
		expect(partial.offset).toBe(2);
		expect(partial.completedAt).toBeUndefined();
		expect(store.readUpload(created.id)?.toString()).toBe('ab');

		const wrongOffset = store.appendUpload({
			uploadId: created.id,
			offset: 0,
			chunk: Buffer.from('x')
		});
		await expect(wrongOffset).rejects.toBeInstanceOf(TusUploadOffsetError);
		await expect(wrongOffset).rejects.toMatchObject({ currentOffset: 2 });
		await expect(
			store.appendUpload({
				uploadId: created.id,
				offset: 2,
				chunk: Buffer.from('toolong')
			})
		).rejects.toBeInstanceOf(TusUploadExceedsLengthError);

		const completed = await store.appendUpload({
			uploadId: created.id,
			offset: 2,
			chunk: Buffer.from('cde')
		});
		expect(completed.offset).toBe(5);
		expect(completed.completedAt).toBeInstanceOf(Date);
		expect(store.readUpload(created.id)?.toString()).toBe('abcde');

		expect(await store.deleteUpload(created.id)).toBe(true);
		expect(await store.deleteUpload(created.id)).toBe(false);
		expect(await store.getUpload(created.id)).toBeNull();
		expect(store.readUpload(created.id)).toBeNull();
	});

	it('enforces aggregate byte and retained-upload limits and releases capacity on delete', async () => {
		const byteLimited = new MemoryTusUploadStore({ maxBytes: 5, maxUploads: 10 });
		await byteLimited.createUpload({ id: 'first', length: 3, metadata: {} });
		await expect(byteLimited.createUpload({ id: 'second', length: 3, metadata: {} })).rejects.toBeInstanceOf(
			TusUploadCapacityError
		);

		await byteLimited.deleteUpload('first');
		await expect(byteLimited.createUpload({ id: 'second', length: 5, metadata: {} })).resolves.toMatchObject({
			id: 'second',
			length: 5
		});

		const countLimited = new MemoryTusUploadStore({ maxBytes: 100, maxUploads: 1 });
		await countLimited.createUpload({ id: 'only', length: 1, metadata: {} });
		await expect(countLimited.createUpload({ id: 'extra', length: 1, metadata: {} })).rejects.toThrow(
			/limited to 1 uploads/
		);
	});

	it('uses a 30 MiB aggregate limit by default', async () => {
		const store = new MemoryTusUploadStore();
		await expect(
			store.createUpload({
				id: 'too-large-for-default-memory',
				length: 30 * 1024 * 1024 + 1,
				metadata: {}
			})
		).rejects.toThrow(`limited to ${30 * 1024 * 1024} bytes`);
	});

	it('rejects duplicate IDs without changing reserved capacity', async () => {
		const store = new MemoryTusUploadStore({ maxBytes: 4 });
		await store.createUpload({ id: 'same', length: 2, metadata: {} });
		await expect(store.createUpload({ id: 'same', length: 2, metadata: {} })).rejects.toThrow(
			'Upload same already exists'
		);
		await expect(store.createUpload({ id: 'other', length: 2, metadata: {} })).resolves.toMatchObject({
			id: 'other'
		});
	});

	it('purges only stale incomplete uploads and frees their reserved bytes', async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
		const store = new MemoryTusUploadStore({ maxBytes: 8, maxUploads: 10 });

		const stale = await store.createUpload({ id: 'stale', length: 4, metadata: {} });
		await store.appendUpload({
			uploadId: stale.id,
			offset: 0,
			chunk: Buffer.from('ab')
		});
		const completed = await store.createUpload({ id: 'completed', length: 1, metadata: {} });
		await store.appendUpload({
			uploadId: completed.id,
			offset: 0,
			chunk: Buffer.from('x')
		});

		vi.setSystemTime(new Date('2026-01-01T00:02:00.000Z'));
		await store.createUpload({ id: 'fresh', length: 2, metadata: {} });
		const result = await store.purgeExpired(new Date('2026-01-01T00:01:00.000Z'));

		expect(result).toEqual({ uploads: 1, bytes: 2 });
		expect(await store.getUpload('stale')).toBeNull();
		expect(await store.getUpload('completed')).not.toBeNull();
		expect(await store.getUpload('fresh')).not.toBeNull();
		await expect(store.createUpload({ id: 'reuses-capacity', length: 4, metadata: {} })).resolves.toBeTruthy();
	});
});
