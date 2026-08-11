#!/usr/bin/env node

const { execFileSync } = require('node:child_process');
const { mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const packageRoot = path.resolve(__dirname, '..');
const testRoot = mkdtempSync(path.join(tmpdir(), 'apicore-client-package-'));

const run = (command, args) =>
	execFileSync(command, args, {
		cwd: testRoot,
		encoding: 'utf8',
		stdio: ['ignore', 'pipe', 'inherit']
	});

try {
	const packResult = JSON.parse(
		run(npmCommand, ['pack', packageRoot, '--pack-destination', testRoot, '--ignore-scripts', '--json'])
	);
	const packEntries = Array.isArray(packResult) ? packResult : Object.values(packResult);
	const tarballName = packEntries[0]?.filename;
	if (!tarballName) {
		throw new Error('npm pack did not return a package filename');
	}
	const packedFiles = new Set(packEntries[0]?.files?.map((file) => file.path));
	for (const required of ['README.md', 'CHANGES.md']) {
		if (!packedFiles.has(required)) {
			throw new Error(`Packed client package is missing ${required}`);
		}
	}

	writeFileSync(
		path.join(testRoot, 'package.json'),
		JSON.stringify({ name: 'apicore-client-package-test', private: true }, null, '\t') + '\n',
		'utf8'
	);
	run(npmCommand, [
		'install',
		'--ignore-scripts',
		'--no-audit',
		'--no-fund',
		'--package-lock=false',
		path.join(testRoot, tarballName)
	]);

	run(process.execPath, [
		'--eval',
		`
			const assert = require('node:assert/strict');
			const client = require('@technomoron/apicore-client');
			assert.equal(typeof client.default, 'function');
			assert.equal(typeof client.ApiClient, 'function');
			assert.equal(typeof client.ApiResponse, 'function');
		`
	]);
	run(process.execPath, [
		'--input-type=module',
		'--eval',
		`
			import assert from 'node:assert/strict';
			const client = await import('@technomoron/apicore-client');
			assert.equal(typeof client.default, 'function');
			assert.equal(typeof client.ApiClient, 'function');
			assert.equal(typeof client.ApiResponse, 'function');
		`
	]);
} finally {
	rmSync(testRoot, { recursive: true, force: true });
}
