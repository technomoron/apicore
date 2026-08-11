import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiError } from '../../../src/apicore-server';
import { MemoryTusUploadStore } from '../../../src/upload/memory';
import { TusUploadModule } from '../../../src/upload/tus-module';
import { createServer, signToken } from '../../helpers/test-server';

function b64(value: string): string {
	return Buffer.from(value, 'utf8').toString('base64');
}

describe('TusUploadModule', () => {
	const tempDirs: string[] = [];

	afterEach(() => {
		for (const dir of tempDirs.splice(0)) {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('requires an explicit authentication policy', () => {
		expect(() => new TusUploadModule(undefined as never)).toThrow(/explicit auth option/i);
	});

	it('rejects a custom store combined with a storage path', () => {
		expect(
			() =>
				new TusUploadModule({
					auth: { type: 'none', req: 'any' },
					store: new MemoryTusUploadStore(),
					storagePath: '/tmp/not-used'
				})
		).toThrow(/cannot be combined/);
	});

	it('creates uploads, supports chunk append, and triggers completion callback once complete', async () => {
		const store = new MemoryTusUploadStore();
		const onComplete = vi.fn();
		const server = createServer();
		server.api(
			new TusUploadModule({
				basePath: '/api/v1/upload',
				store,
				auth: { type: 'none', req: 'any' },
				onUploadComplete: onComplete
			})
		);

		const createRes = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '11')
			.set('Upload-Metadata', `filename ${b64('video.mp4')},kind ${b64('demo')}`);

		expect(createRes.status).toBe(201);
		expect(createRes.headers['tus-resumable']).toBe('1.0.0');
		const location = String(createRes.headers.location || '');
		expect(location.startsWith('/api/v1/upload/')).toBe(true);

		const firstChunk = await request(server.app)
			.patch(location)
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Offset', '0')
			.set('Content-Type', 'application/offset+octet-stream')
			.send(Buffer.from('hello ', 'utf8'));
		expect(firstChunk.status).toBe(204);
		expect(firstChunk.headers['upload-offset']).toBe('6');
		expect(onComplete).toHaveBeenCalledTimes(0);

		const headRes = await request(server.app).head(location).set('Tus-Resumable', '1.0.0');
		expect(headRes.status).toBe(200);
		expect(headRes.headers['upload-offset']).toBe('6');
		expect(headRes.headers['upload-length']).toBe('11');

		const secondChunk = await request(server.app)
			.patch(location)
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Offset', '6')
			.set('Content-Type', 'application/offset+octet-stream')
			.send(Buffer.from('world', 'utf8'));
		expect(secondChunk.status).toBe(204);
		expect(secondChunk.headers['upload-offset']).toBe('11');
		expect(onComplete).toHaveBeenCalledTimes(1);

		const uploadId = location.split('/').pop() || '';
		expect(store.readUpload(uploadId)?.toString('utf8')).toBe('hello world');
	});

	it('uses a file store, the global upload limit, and 5 MiB chunks by default', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-tus-'));
		tempDirs.push(uploadPath);
		const onComplete = vi.fn();
		const server = createServer({ uploadPath, uploadMax: 6, uploadCleanup: 'off' });
		server.api(
			new TusUploadModule({
				auth: { type: 'none', req: 'any' },
				onUploadComplete: onComplete
			})
		);

		const optionsRes = await request(server.app).options('/api/v1/upload');
		expect(optionsRes.status).toBe(204);
		expect(optionsRes.headers['tus-max-size']).toBe('6');
		expect(optionsRes.headers['tus-extension']).toContain('expiration');

		const rejected = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '7');
		expect(rejected.status).toBe(413);

		const created = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '6');
		expect(created.status).toBe(201);
		expect(created.headers['upload-expires']).toBeTruthy();

		const completed = await request(server.app)
			.patch(String(created.headers.location))
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Offset', '0')
			.set('Content-Type', 'application/offset+octet-stream')
			.send(Buffer.from('video!', 'utf8'));
		expect(completed.status).toBe(204);
		expect(onComplete).toHaveBeenCalledTimes(1);
		const record = onComplete.mock.calls[0]?.[0];
		expect(record?.filepath).toBe(path.join(uploadPath, 'tus', `${record?.id}.upload`));
		expect(fs.readFileSync(record?.filepath, 'utf8')).toBe('video!');
	});

	it('supports an explicit TUS storage path', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-tus-'));
		tempDirs.push(uploadPath);
		const storagePath = path.join(uploadPath, 'resumable');
		const server = createServer({ uploadPath, uploadCleanup: 'off' });
		server.api(
			new TusUploadModule({
				auth: { type: 'none', req: 'any' },
				storagePath
			})
		);

		const created = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '1');
		const uploadId = String(created.headers.location).split('/').pop();

		expect(created.status).toBe(201);
		expect(fs.existsSync(path.join(storagePath, `${uploadId}.upload`))).toBe(true);
		expect(fs.existsSync(path.join(uploadPath, 'tus'))).toBe(false);
	});

	it('runs upload validation before creating a file', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-tus-'));
		tempDirs.push(uploadPath);
		const server = createServer({ uploadPath, uploadCleanup: 'off' });
		server.api(
			new TusUploadModule({
				auth: { type: 'none', req: 'any' },
				validateUpload: ({ length, metadata }) => {
					if (length > 10 || metadata.filetype !== 'video/mp4') {
						throw new ApiError({ code: 415, message: 'Only small MP4 videos are accepted' });
					}
				}
			})
		);

		const response = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '8')
			.set('Upload-Metadata', `filetype ${b64('text/plain')}`);

		expect(response.status).toBe(415);
		expect(response.body.message).toBe('Only small MP4 videos are accepted');
		expect(fs.existsSync(path.join(uploadPath, 'tus'))).toBe(false);
	});

	it('awaits asynchronous upload validation and supplies the owner and declared metadata', async () => {
		const store = new MemoryTusUploadStore();
		const validateUpload = vi.fn(async () => Promise.resolve());
		const server = createServer();
		server.api(
			new TusUploadModule({
				store,
				auth: { type: 'maybe', req: 'any' },
				validateUpload
			})
		);
		const token = signToken(server, { uid: 'user-1', role: 'any' });

		const response = await request(server.app)
			.post('/api/v1/upload')
			.set('Authorization', `Bearer ${token}`)
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '8')
			.set('Upload-Metadata', `filename ${b64('video.mp4')},filetype ${b64('video/mp4')}`);

		expect(response.status).toBe(201);
		expect(validateUpload).toHaveBeenCalledOnce();
		expect(validateUpload).toHaveBeenCalledWith({
			length: 8,
			metadata: {
				filename: 'video.mp4',
				filetype: 'video/mp4'
			},
			userId: 'user-1'
		});
	});

	it('keeps the completed upload when its completion callback fails', async () => {
		const store = new MemoryTusUploadStore();
		const onUploadComplete = vi.fn(async () => {
			throw new Error('processor unavailable');
		});
		const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
		try {
			const server = createServer();
			server.api(
				new TusUploadModule({
					store,
					auth: { type: 'none', req: 'any' },
					onUploadComplete
				})
			);
			const created = await request(server.app)
				.post('/api/v1/upload')
				.set('Tus-Resumable', '1.0.0')
				.set('Upload-Length', '1');
			const uploadId = String(created.headers.location).split('/').pop()!;

			const completed = await request(server.app)
				.patch(String(created.headers.location))
				.set('Tus-Resumable', '1.0.0')
				.set('Upload-Offset', '0')
				.set('Content-Type', 'application/offset+octet-stream')
				.send(Buffer.from('x'));

			expect(completed.status).toBe(204);
			expect(onUploadComplete).toHaveBeenCalledOnce();
			expect(errorSpy).toHaveBeenCalledOnce();
			expect((await store.getUpload(uploadId))?.completedAt).toBeInstanceOf(Date);
			expect(store.readUpload(uploadId)?.toString()).toBe('x');
		} finally {
			errorSpy.mockRestore();
		}
	});

	it('bounds explicitly selected memory storage', async () => {
		const store = new MemoryTusUploadStore({ maxBytes: 4, maxUploads: 2 });
		const server = createServer();
		server.api(new TusUploadModule({ store, auth: { type: 'none', req: 'any' } }));

		const response = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '5');

		expect(response.status).toBe(507);
		expect(response.body.message).toContain('limited to 4 bytes');
	});

	it('applies the global free-disk floor to file-backed TUS uploads', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-tus-'));
		tempDirs.push(uploadPath);
		const server = createServer({
			uploadPath,
			uploadCleanup: 'off',
			uploadMinDiskFreeMB: 1_000_000_000
		});
		server.api(new TusUploadModule({ auth: { type: 'none', req: 'any' } }));

		const response = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '1');

		expect(response.status).toBe(507);
		expect(response.body.message).toMatch(/free disk space/i);
	});

	it('denies anonymous access to an upload owned by an authenticated user', async () => {
		const store = new MemoryTusUploadStore();
		const server = createServer();
		server.api(
			new TusUploadModule({
				store,
				auth: { type: 'maybe', req: 'any' }
			})
		);
		const token = signToken(server, { uid: 'user-1', role: 'any' });
		const created = await request(server.app)
			.post('/api/v1/upload')
			.set('Authorization', `Bearer ${token}`)
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '1');

		const response = await request(server.app).head(String(created.headers.location)).set('Tus-Resumable', '1.0.0');

		expect(response.status).toBe(403);
	});

	it('uses /api/v1/upload as the default resumable upload endpoint', async () => {
		const store = new MemoryTusUploadStore();
		const server = createServer();
		server.api(new TusUploadModule({ store, auth: { type: 'none', req: 'any' } }));

		const createRes = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '1');

		expect(createRes.status).toBe(201);
		expect(String(createRes.headers.location || '')).toMatch(/^\/api\/v1\/upload\//);
	});

	it('returns 409 when chunk offset does not match server offset', async () => {
		const store = new MemoryTusUploadStore();
		const server = createServer();
		server.api(
			new TusUploadModule({
				basePath: '/api/v1/upload',
				store,
				auth: { type: 'none', req: 'any' }
			})
		);

		const createRes = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '4');
		const location = String(createRes.headers.location || '');

		const patchRes = await request(server.app)
			.patch(location)
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Offset', '2')
			.set('Content-Type', 'application/offset+octet-stream')
			.send(Buffer.from('ab', 'utf8'));

		expect(patchRes.status).toBe(409);
		expect(patchRes.headers['upload-offset']).toBe('0');
	});

	it('requires the TUS chunk content type and enforces the configured chunk limit', async () => {
		const store = new MemoryTusUploadStore();
		const server = createServer({ uploadMax: 10 });
		server.api(
			new TusUploadModule({
				store,
				auth: { type: 'none', req: 'any' },
				chunkMaxBytes: 4
			})
		);
		const created = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '10');
		const location = String(created.headers.location);

		const wrongType = await request(server.app)
			.patch(location)
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Offset', '0')
			.set('Content-Type', 'application/octet-stream')
			.send(Buffer.from('ab'));
		expect(wrongType.status).toBe(415);

		const tooLarge = await request(server.app)
			.patch(location)
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Offset', '0')
			.set('Content-Type', 'application/offset+octet-stream')
			.send(Buffer.from('abcde'));
		expect(tooLarge.status).toBe(413);
		expect((await store.getUpload(location.split('/').pop()!))?.offset).toBe(0);
	});

	it('returns 410 and removes an expired incomplete file upload on access', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-tus-'));
		tempDirs.push(uploadPath);
		const server = createServer({
			uploadPath,
			uploadCleanup: 'off',
			uploadOrphanExpirySeconds: 60
		});
		server.api(new TusUploadModule({ auth: { type: 'none', req: 'any' } }));
		const created = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '2');
		const location = String(created.headers.location);
		const uploadId = location.split('/').pop()!;
		const metadataPath = path.join(uploadPath, 'tus', `${uploadId}.json`);
		const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8')) as Record<string, unknown>;
		metadata.updatedAt = new Date(Date.now() - 120_000).toISOString();
		fs.writeFileSync(metadataPath, JSON.stringify(metadata));

		const response = await request(server.app).head(location).set('Tus-Resumable', '1.0.0');

		expect(response.status).toBe(410);
		expect(response.headers['tus-resumable']).toBe('1.0.0');
		expect(fs.existsSync(metadataPath)).toBe(false);
		expect(fs.existsSync(path.join(uploadPath, 'tus', `${uploadId}.upload`))).toBe(false);
	});

	it('rejects invalid upload creation headers through Fastify validation', async () => {
		const store = new MemoryTusUploadStore();
		const server = createServer();
		server.api(
			new TusUploadModule({
				basePath: '/api/v1/upload',
				store,
				auth: { type: 'none', req: 'any' }
			})
		);

		const response = await request(server.app).post('/api/v1/upload').set('Upload-Length', '0');

		expect(response.status).toBe(400);
		expect(response.body.message).toBe('Validation failed');
		expect(response.body.errors).toHaveProperty('tus-resumable');
		expect(response.body.errors).toHaveProperty('upload-length');
	});
});
