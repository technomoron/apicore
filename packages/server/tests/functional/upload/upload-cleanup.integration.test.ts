import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { TusUploadModule } from '../../../src/upload/tus-module';
import { createServer, signToken } from '../../helpers/test-server';

describe('Upload cleanup', () => {
	const tempDirs: string[] = [];

	afterEach(() => {
		vi.restoreAllMocks();
		for (const dir of tempDirs.splice(0)) {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	function createStagedMimeFile(uploadPath: string, name: string, ageMs: number): string {
		const mimePath = path.join(uploadPath, 'mime');
		fs.mkdirSync(mimePath, { recursive: true });
		const filepath = path.join(mimePath, name);
		fs.writeFileSync(filepath, Buffer.from(name));
		const modifiedAt = new Date(Date.now() - ageMs);
		fs.utimesSync(filepath, modifiedAt, modifiedAt);
		return filepath;
	}

	it('runs lazy cleanup before the first file-backed upload without using a timer', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-cleanup-'));
		tempDirs.push(uploadPath);
		const stalePath = createStagedMimeFile(uploadPath, 'stale.bin', 120_000);
		const freshPath = createStagedMimeFile(uploadPath, 'fresh.bin', 1_000);
		const server = createServer({
			uploadPath,
			uploadOrphanExpirySeconds: 60
		});
		const purgeSpy = vi.spyOn(server, 'purgeOrphanedUploads');

		await server.prepareUploadDirectory(server.getUploadPath('tus'));
		await vi.waitFor(() => {
			expect(fs.existsSync(stalePath)).toBe(false);
		});

		expect(server.config.uploadCleanup).toBe('lazy');
		expect(purgeSpy).toHaveBeenCalledOnce();
		expect(fs.existsSync(freshPath)).toBe(true);

		await server.prepareUploadDirectory(server.getUploadPath('tus'));
		expect(purgeSpy).toHaveBeenCalledOnce();
	});

	it('does not run automatic cleanup when cleanup is off', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-cleanup-'));
		tempDirs.push(uploadPath);
		const stalePath = createStagedMimeFile(uploadPath, 'stale.bin', 120_000);
		const server = createServer({
			uploadPath,
			uploadCleanup: 'off',
			uploadOrphanExpirySeconds: 60
		});
		const purgeSpy = vi.spyOn(server, 'purgeOrphanedUploads');

		await server.prepareUploadDirectory(server.getUploadPath('tus'));

		expect(purgeSpy).not.toHaveBeenCalled();
		expect(fs.existsSync(stalePath)).toBe(true);
	});

	it('runs interval cleanup and stops its timer when Fastify closes', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-cleanup-'));
		tempDirs.push(uploadPath);
		const stalePath = createStagedMimeFile(uploadPath, 'stale.bin', 120_000);
		const server = createServer({
			uploadPath,
			uploadCleanup: 'interval',
			uploadCleanupIntervalSeconds: 0.01,
			uploadOrphanExpirySeconds: 60
		});
		const purgeSpy = vi.spyOn(server, 'purgeOrphanedUploads');

		await server.fastify.ready();
		await vi.waitFor(() => {
			expect(fs.existsSync(stalePath)).toBe(false);
		});
		expect(purgeSpy).toHaveBeenCalled();

		await server.fastify.close();
		const callsAfterClose = purgeSpy.mock.calls.length;
		await new Promise((resolve) => setTimeout(resolve, 30));
		expect(purgeSpy).toHaveBeenCalledTimes(callsAfterClose);
	});

	it('runs one cleanup attempt on low disk even when automatic cleanup is off', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-cleanup-'));
		tempDirs.push(uploadPath);
		const stalePath = createStagedMimeFile(uploadPath, 'stale.bin', 120_000);
		const server = createServer({
			uploadPath,
			uploadCleanup: 'off',
			uploadOrphanExpirySeconds: 60,
			uploadMinDiskFreeMB: 1_000_000_000
		});
		const purgeSpy = vi.spyOn(server, 'purgeOrphanedUploads');

		await expect(server.prepareUploadDirectory(server.getUploadPath('tus'), 1)).rejects.toMatchObject({
			code: 507
		});

		expect(purgeSpy).toHaveBeenCalledOnce();
		expect(fs.existsSync(stalePath)).toBe(false);
	});

	it('lets strict administrators purge stale MIME files and incomplete TUS uploads', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-cleanup-'));
		tempDirs.push(uploadPath);
		const server = createServer({
			uploadPath,
			uploadCleanup: 'off',
			uploadOrphanExpirySeconds: 60
		});
		server.api(new TusUploadModule({ auth: { type: 'none', req: 'any' } }));

		const incomplete = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '10');
		const incompleteId = String(incomplete.headers.location).split('/').pop()!;

		const freshIncomplete = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '10');
		const freshIncompleteId = String(freshIncomplete.headers.location).split('/').pop()!;

		const completed = await request(server.app)
			.post('/api/v1/upload')
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Length', '1');
		const completedId = String(completed.headers.location).split('/').pop()!;
		await request(server.app)
			.patch(String(completed.headers.location))
			.set('Tus-Resumable', '1.0.0')
			.set('Upload-Offset', '0')
			.set('Content-Type', 'application/offset+octet-stream')
			.send(Buffer.from('x'));

		const oldDate = new Date(Date.now() - 120_000);
		for (const uploadId of [incompleteId, completedId]) {
			const metadataPath = path.join(uploadPath, 'tus', `${uploadId}.json`);
			const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8')) as Record<string, unknown>;
			metadata.updatedAt = oldDate.toISOString();
			fs.writeFileSync(metadataPath, JSON.stringify(metadata));
		}

		const mimePath = path.join(uploadPath, 'mime');
		fs.mkdirSync(mimePath, { recursive: true });
		const staleMimePath = path.join(mimePath, 'stale-upload.bin');
		fs.writeFileSync(staleMimePath, Buffer.from('mime'));
		fs.utimesSync(staleMimePath, oldDate, oldDate);
		const freshMimePath = path.join(mimePath, 'fresh-upload.bin');
		fs.writeFileSync(freshMimePath, Buffer.from('fresh'));

		const denied = await request(server.app).post('/api/v1/uploads/purge');
		expect(denied.status).toBe(401);

		const userToken = signToken(server, { uid: 'user-1', role: 'any' });
		await server.storage.storeToken({
			accessToken: userToken,
			refreshToken: 'user-refresh',
			userId: 'user-1'
		});
		const forbidden = await request(server.app)
			.post('/api/v1/uploads/purge')
			.set('Authorization', `Bearer ${userToken}`);
		expect(forbidden.status).toBe(403);

		const adminToken = signToken(server, { uid: 'admin-1', role: 'admin' });
		await server.storage.storeToken({
			accessToken: adminToken,
			refreshToken: 'admin-refresh',
			userId: 'admin-1'
		});
		const response = await request(server.app)
			.post('/api/v1/uploads/purge')
			.set('Authorization', `Bearer ${adminToken}`);

		expect(response.status).toBe(200);
		expect(response.body.data).toMatchObject({
			mime: { uploads: 1, bytes: 4 },
			tus: { uploads: 1, bytes: 0 },
			total: { uploads: 2, bytes: 4 }
		});
		expect(fs.existsSync(staleMimePath)).toBe(false);
		expect(fs.existsSync(path.join(uploadPath, 'tus', `${incompleteId}.json`))).toBe(false);
		expect(fs.existsSync(path.join(uploadPath, 'tus', `${incompleteId}.upload`))).toBe(false);
		expect(fs.existsSync(freshMimePath)).toBe(true);
		expect(fs.existsSync(path.join(uploadPath, 'tus', `${freshIncompleteId}.json`))).toBe(true);
		expect(fs.existsSync(path.join(uploadPath, 'tus', `${freshIncompleteId}.upload`))).toBe(true);
		expect(fs.existsSync(path.join(uploadPath, 'tus', `${completedId}.json`))).toBe(true);
		expect(fs.existsSync(path.join(uploadPath, 'tus', `${completedId}.upload`))).toBe(true);
	});
});
