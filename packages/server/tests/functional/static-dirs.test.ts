import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import request from 'supertest';
import { beforeEach, afterEach, describe, it, expect } from 'vitest';

import { createServer } from '../helpers/test-server';

describe('Static directory mounts', () => {
	let rootDir: string;
	let assetsDir: string;
	let docsDir: string;

	beforeEach(() => {
		rootDir = fs.mkdtempSync(path.join(os.tmpdir(), 'apicore-static-'));
		assetsDir = path.join(rootDir, 'assets');
		docsDir = path.join(rootDir, 'docs');
		fs.mkdirSync(assetsDir, { recursive: true });
		fs.mkdirSync(docsDir, { recursive: true });
		fs.writeFileSync(path.join(assetsDir, 'hello.txt'), 'hello world', 'utf8');
		fs.writeFileSync(path.join(docsDir, 'readme.txt'), 'docs here', 'utf8');
	});

	afterEach(() => {
		if (rootDir) {
			fs.rmSync(rootDir, { recursive: true, force: true });
		}
	});

	it('serves assets from configured static directories', async () => {
		const server = createServer({
			staticDirs: {
				'/assets': assetsDir,
				'/docs': docsDir
			}
		});

		const assets = await request(server.app).get('/assets/hello.txt');
		expect(assets.status).toBe(200);
		expect(assets.text).toBe('hello world');

		const docs = await request(server.app).get('/docs/readme.txt');
		expect(docs.status).toBe(200);
		expect(docs.text).toBe('docs here');
	});
});
