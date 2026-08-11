import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';

import { ApiModule, type ApiRoute, type ExtendedReq } from '../../src/apicore-server';
import { createServer } from '../helpers/test-server';

class UploadModule extends ApiModule {
	public static override defaultNamespace = '/upload';

	public override defineRoutes(): ApiRoute[] {
		return [
			{
				method: 'post',
				path: '/test',
				auth: { type: 'none', req: 'any' },
				handler: async ({ req }) => {
					const files = (req as ExtendedReq).files;
					const list = Array.isArray(files) ? files : [];
					const first = list[0] ?? null;
					return [
						200,
						{
							count: list.length,
							first: first
								? {
										originalname: first.originalname,
										size: first.size ?? null,
										filepath: first.filepath ?? null,
										hasBuffer: Buffer.isBuffer(first.buffer)
									}
								: null,
							body: (req.body ?? null) as Record<string, unknown> | null
						}
					];
				}
			}
		];
	}
}

describe('Upload handling', () => {
	const tempDirs: string[] = [];

	afterEach(() => {
		for (const dir of tempDirs.splice(0)) {
			try {
				fs.rmSync(dir, { recursive: true, force: true });
			} catch {
				// ignore cleanup failures
			}
		}
	});

	it('stages enabled multipart uploads under uploadPath/mime', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-upload-'));
		tempDirs.push(uploadPath);

		const server = createServer({ uploadPath, uploadMax: 128, multipartEnabled: true });
		server.api(new UploadModule());

		const response = await request(server.app)
			.post('/api/upload/test')
			.field('title', 'demo')
			.attach('file', Buffer.from('abc', 'utf8'), 'sample.txt');

		expect(response.status).toBe(200);
		expect(response.body.data.count).toBe(1);
		expect(response.body.data.first).toMatchObject({
			originalname: 'sample.txt',
			size: 3,
			hasBuffer: false
		});
		expect(response.body.data.body).toEqual({ title: 'demo' });
		expect(typeof response.body.data.first.filepath).toBe('string');
		expect(path.dirname(response.body.data.first.filepath)).toBe(path.join(uploadPath, 'mime'));
		expect(fs.existsSync(response.body.data.first.filepath)).toBe(true);
		expect(fs.readFileSync(response.body.data.first.filepath, 'utf8')).toBe('abc');
	});

	it('keeps multipart parsing disabled until explicitly enabled', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-upload-'));
		tempDirs.push(uploadPath);
		const server = createServer({ uploadPath, uploadMax: 128 });
		server.api(new UploadModule());

		const response = await request(server.app)
			.post('/api/upload/test')
			.field('title', 'demo')
			.attach('file', Buffer.from('abc', 'utf8'), 'sample.txt');

		expect(response.status).toBe(415);
		expect(fs.existsSync(path.join(uploadPath, 'mime'))).toBe(false);
	});

	it('leaves multipart streams available to custom Fastify routes', async () => {
		const server = createServer({ multipartEnabled: true, uploadMax: 128 });

		server.fastify.post('/raw-upload', async (req) => {
			const file = await req.file();
			const buffer = file ? await file.toBuffer() : null;
			return {
				filename: file?.filename ?? null,
				size: buffer?.length ?? 0
			};
		});

		const response = await request(server.app)
			.post('/raw-upload')
			.attach('file', Buffer.from('abc', 'utf8'), 'sample.txt');

		expect(response.status).toBe(200);
		expect(response.body).toEqual({
			filename: 'sample.txt',
			size: 3
		});
	});

	it('exposes the raw request stream to compatibility upload routes', async () => {
		const server = createServer({ multipartEnabled: true, uploadMax: 128 });

		server.useExpress('/compat-upload', async (req, res) => {
			const file = await req.fastifyRequest.file();
			const buffer = file ? await file.toBuffer() : null;
			res.status(200).json({
				hasOn: typeof req.on === 'function',
				hasPipe: typeof req.pipe === 'function',
				filename: file?.filename ?? null,
				size: buffer?.length ?? 0,
				preparsedFiles: Array.isArray(req.files) ? req.files.length : null
			});
		});

		const response = await request(server.app)
			.post('/compat-upload')
			.attach('file', Buffer.from('abc', 'utf8'), 'sample.txt');

		expect(response.status).toBe(200);
		expect(response.body).toEqual({
			hasOn: true,
			hasPipe: true,
			filename: 'sample.txt',
			size: 3,
			preparsedFiles: null
		});
	});

	it('denies disk-backed uploads when free disk space falls below the configured MB threshold', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-upload-'));
		tempDirs.push(uploadPath);

		const server = createServer({
			uploadPath,
			uploadMax: 128,
			multipartEnabled: true,
			uploadMinDiskFreeMB: 1_000_000_000
		});
		server.api(new UploadModule());

		const response = await request(server.app)
			.post('/api/upload/test')
			.attach('file', Buffer.from('abc', 'utf8'), 'sample.txt');

		expect(response.status).toBe(507);
		expect(response.body.success).toBe(false);
		expect(response.body.message).toMatch(/free disk space/i);
	});

	it('denies disk-backed uploads when free disk space falls below the configured percent threshold', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-upload-'));
		tempDirs.push(uploadPath);

		const server = createServer({
			uploadPath,
			uploadMax: 128,
			multipartEnabled: true,
			uploadMinDiskFreePercent: 101
		});
		server.api(new UploadModule());

		const response = await request(server.app)
			.post('/api/upload/test')
			.attach('file', Buffer.from('abc', 'utf8'), 'sample.txt');

		expect(response.status).toBe(507);
		expect(response.body.success).toBe(false);
		expect(response.body.message).toMatch(/free disk space/i);
	});

	it('rejects files larger than uploadMax', async () => {
		const uploadPath = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-upload-'));
		tempDirs.push(uploadPath);

		const server = createServer({ uploadPath, uploadMax: 32, multipartEnabled: true });
		server.api(new UploadModule());

		const response = await request(server.app)
			.post('/api/upload/test')
			.attach('file', Buffer.alloc(33, 0x41), 'too-big.bin');

		expect(response.status).toBe(413);
		expect(response.body).toEqual({
			success: false,
			code: 413,
			message: 'Upload exceeds maximum size of 32 bytes',
			data: null,
			errors: {}
		});
	});
});
