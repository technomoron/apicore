#!/usr/bin/env node

const { execFileSync } = require('node:child_process');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const packageRoot = path.resolve(__dirname, '..');
const testRoot = mkdtempSync(path.join(tmpdir(), 'apicore-server-package-'));

try {
	const output = execFileSync(
		npmCommand,
		['pack', packageRoot, '--pack-destination', testRoot, '--ignore-scripts', '--json', '--dry-run'],
		{
			cwd: testRoot,
			encoding: 'utf8',
			stdio: ['ignore', 'pipe', 'inherit']
		}
	);
	const result = JSON.parse(output);
	const entries = Array.isArray(result) ? result : Object.values(result);
	const files = new Set(entries[0]?.files?.map((file) => file.path));
	for (const required of [
		'README.md',
		'CHANGES.md',
		'docs/README.md',
		'docs/configuration.md',
		'docs/architecture.md',
		'docs/base/README.md',
		'docs/auth/README.md',
		'docs/passkey/README.md',
		'docs/oauth/README.md',
		'docs/uploads/README.md',
		'docs/swagger/openapi.json'
	]) {
		if (!files.has(required)) {
			throw new Error(`Packed server package is missing ${required}`);
		}
	}
} finally {
	rmSync(testRoot, { recursive: true, force: true });
}
