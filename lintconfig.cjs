#!/usr/bin/env node

const { spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const REPO = 'technomoron/vscode-eslint-defaults';
const RELEASE_API_URL = `https://api.github.com/repos/${REPO}/releases/latest`;
const INSTALLER_ASSET_NAME = 'installer.tgz';
const CHECKSUM_ASSET_NAME = `${INSTALLER_ASSET_NAME}.sha256`;
const REQUEST_TIMEOUT_MS = 60000;
const USER_AGENT = 'vscode-eslint-defaults-lintconfig';

function requestHeaders(extra = {}) {
	const headers = { 'User-Agent': USER_AGENT, ...extra };
	// Raises the anonymous 60 requests/hour API limit, which shared CI egress
	// addresses run into easily.
	const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
	if (token) {
		headers.Authorization = `Bearer ${token}`;
	}
	return headers;
}

async function httpGet(url, headers) {
	const response = await fetch(url, {
		headers: requestHeaders(headers),
		signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
	});

	if (!response.ok) {
		throw new Error(`Failed to fetch ${url}: ${response.status} ${response.statusText}`);
	}

	return response;
}

async function fetchJson(url) {
	const response = await httpGet(url, { Accept: 'application/vnd.github+json' });
	return response.json();
}

async function fetchBuffer(url) {
	const response = await httpGet(url);
	return Buffer.from(await response.arrayBuffer());
}

async function fetchText(url) {
	const response = await httpGet(url);
	return response.text();
}

function getTarCommand() {
	if (process.platform !== 'win32') {
		return 'tar';
	}

	const systemRoot = process.env.SystemRoot || 'C:\\Windows';
	const candidates = [
		path.join(systemRoot, 'System32', 'tar.exe'),
		path.join(systemRoot, 'Sysnative', 'tar.exe')
	];

	const tarPath = candidates.find((candidate) => fs.existsSync(candidate));
	if (!tarPath) {
		throw new Error(`Windows tar.exe not found under ${systemRoot}.`);
	}

	return tarPath;
}

function extractArchive(archivePath, destination) {
	const result = spawnSync(getTarCommand(), ['-xzf', archivePath, '-C', destination], {
		stdio: 'inherit'
	});

	if (result.error) {
		throw result.error;
	}

	if (result.status !== 0) {
		throw new Error(`Failed to extract ${INSTALLER_ASSET_NAME}.`);
	}
}

// Checksums are published alongside the archive. A release without one is older
// than this check, so it warns instead of failing.
function verifyChecksum(archive, checksumText) {
	const expected = String(checksumText).trim().split(/\s+/)[0]?.toLowerCase();
	if (!expected || !/^[a-f0-9]{64}$/.test(expected)) {
		throw new Error(`Malformed ${CHECKSUM_ASSET_NAME} contents.`);
	}

	const actual = crypto.createHash('sha256').update(archive).digest('hex');
	if (actual !== expected) {
		throw new Error(`Checksum mismatch for ${INSTALLER_ASSET_NAME}: expected ${expected}, got ${actual}.`);
	}

	console.log('Installer checksum verified.');
}

function parseArgs(argv) {
	const passthrough = [];
	let version = process.env.VSCODE_ESLINT_DEFAULTS_VERSION || 'latest';

	for (let index = 0; index < argv.length; index += 1) {
		const arg = argv[index];
		if (arg === '--latest') {
			version = 'latest';
		} else if (arg.startsWith('--version=')) {
			version = arg.slice('--version='.length);
		} else if (arg === '--version') {
			const value = argv[index + 1];
			if (!value || value.startsWith('-')) {
				throw new Error('Missing value for --version.');
			}
			version = value;
			index += 1;
		} else {
			passthrough.push(arg);
		}
	}

	return { version: version.replace(/^v/, ''), passthrough };
}

async function resolveAssetUrls(version) {
	if (version === 'latest') {
		const release = await fetchJson(RELEASE_API_URL);
		const assets = Array.isArray(release.assets) ? release.assets : [];
		const archive = assets.find((item) => item.name === INSTALLER_ASSET_NAME);
		const checksum = assets.find((item) => item.name === CHECKSUM_ASSET_NAME);

		if (!archive?.browser_download_url) {
			throw new Error(`Latest release does not include ${INSTALLER_ASSET_NAME}.`);
		}

		return {
			archiveUrl: archive.browser_download_url,
			checksumUrl: checksum?.browser_download_url || null,
			label: release.tag_name || 'latest'
		};
	}

	const base = `https://github.com/${REPO}/releases/download/v${version}`;
	return {
		archiveUrl: `${base}/${INSTALLER_ASSET_NAME}`,
		checksumUrl: `${base}/${CHECKSUM_ASSET_NAME}`,
		label: `v${version}`
	};
}

async function run() {
	const { version, passthrough } = parseArgs(process.argv.slice(2));
	const { archiveUrl, checksumUrl, label } = await resolveAssetUrls(version);

	console.log(`Downloading installer ${label}...`);
	const archive = await fetchBuffer(archiveUrl);

	if (checksumUrl) {
		try {
			verifyChecksum(archive, await fetchText(checksumUrl));
		} catch (error) {
			if (/Failed to fetch/.test(error.message)) {
				console.warn(`No ${CHECKSUM_ASSET_NAME} published for ${label}; skipping checksum verification.`);
			} else {
				throw error;
			}
		}
	} else {
		console.warn(`No ${CHECKSUM_ASSET_NAME} published for ${label}; skipping checksum verification.`);
	}

	// The archive is unpacked outside the project. configure-eslint.cjs copies
	// what it needs from here, so nothing in the project is overwritten blindly.
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lintconfig-'));

	try {
		const archivePath = path.join(tempDir, INSTALLER_ASSET_NAME);
		fs.writeFileSync(archivePath, archive);
		extractArchive(archivePath, tempDir);

		const configurePath = path.join(tempDir, 'configure-eslint.cjs');
		if (!fs.existsSync(configurePath)) {
			throw new Error('configure-eslint.cjs not found after extraction.');
		}

		const result = spawnSync(process.execPath, [configurePath, ...passthrough], {
			stdio: 'inherit',
			cwd: process.cwd()
		});

		if (result.error) {
			throw result.error;
		}
		if (result.status !== 0) {
			process.exitCode = result.status ?? 1;
		}
	} finally {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

run().catch((error) => {
	console.error(error.message || error);
	process.exit(1);
});
