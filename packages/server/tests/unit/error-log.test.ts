import { appendFile } from 'node:fs/promises';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { createErrorId, logError } from '../../src/base/error-log';

vi.mock('node:fs/promises', () => ({ appendFile: vi.fn().mockResolvedValue(undefined) }));

describe('Error diagnostics', () => {
	afterEach(() => vi.restoreAllMocks());

	it('redacts nested credentials, configured secrets, and credentials in messages', () => {
		const cause = Object.assign(
			new Error('failed\nhttps://user:pass@host/path?api_key=abc Bearer xyz password="two words" jwt-secret'),
			{
				password: 'private',
				nested: { refreshToken: 'private', authorization: 'private' },
				cause: new Error('inner failure')
			}
		);
		Object.assign(cause, { self: cause });
		logError('../example', createErrorId(), 'test', cause, ['jwt-secret']);
		const call = vi.mocked(appendFile).mock.calls.at(-1)!;
		expect(call[0]).toBe('/var/log/apicore-___example.log');
		const line = String(call[1]);
		for (const secret of ['user:pass', 'abc', 'xyz', 'two words', 'jwt-secret', 'private']) {
			expect(line).not.toContain(secret);
		}
		expect(line.trim().split('\n')).toHaveLength(1);
		expect(line).toContain('inner failure');
		expect(line).toContain('[Circular]');
	});

	it('keeps redacted diagnostics on stderr when the file cannot be written', async () => {
		vi.mocked(appendFile).mockRejectedValueOnce(new Error('Permission denied'));
		const stderr = vi.spyOn(console, 'error').mockImplementation(() => {});
		const errorId = createErrorId();
		logError('test', errorId, 'test', new Error('failed password=private'), []);
		await Promise.resolve();
		expect(stderr).toHaveBeenCalledOnce();
		const line = String(stderr.mock.calls[0][0]);
		expect(JSON.parse(line)).toMatchObject({ errorId, pid: process.pid });
		expect(line).not.toContain('private');
	});

	it('generates distinct URL-safe IDs of exactly twelve characters', () => {
		const ids = Array.from({ length: 100 }, () => createErrorId());
		expect(new Set(ids).size).toBe(100);
		for (const id of ids) {
			expect(id).toMatch(/^[A-Za-z0-9_-]{12}$/);
		}
	});
});
