#!/usr/bin/env node

/**
 * Ensure the CommonJS build uses .cjs extensions so Node treats it correctly
 * even though the package itself is marked with "type": "module".
 *
 * Recursively walks dist/cjs/, rewrites require('./...js') → require('./...cjs'),
 * and renames every .js file to .cjs.
 */

const fs = require('fs');
const path = require('path');

const distDir = path.join(__dirname, '..', 'dist', 'cjs');
const verbose = process.env.PREPARE_CJS_VERBOSE === '1';

const log = (fn, message) => {
	if (verbose) {
		fn(message);
	}
};

if (!fs.existsSync(distDir)) {
	log(console.warn, '[prepare-cjs] dist/cjs does not exist; skipping');
	process.exit(0);
}

function walk(dir) {
	const entries = fs.readdirSync(dir, { withFileTypes: true });
	const files = [];
	for (const entry of entries) {
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) {
			files.push(...walk(full));
		} else if (entry.isFile() && entry.name.endsWith('.js')) {
			files.push(full);
		}
	}
	return files;
}

const jsFiles = walk(distDir);

for (const filePath of jsFiles) {
	let content = fs.readFileSync(filePath, 'utf8');

	// Rewrite require("./...js") and require("../...js") specifiers to .cjs
	content = content.replace(/(require\(["'])(\.\.?\/[^"']*?)\.js(["']\))/g, '$1$2.cjs$3');

	const cjsPath = filePath.replace(/\.js$/, '.cjs');
	fs.writeFileSync(cjsPath, content, 'utf8');

	if (filePath !== cjsPath) {
		fs.unlinkSync(filePath);
		log(console.log, `[prepare-cjs] ${path.relative(distDir, filePath)} -> ${path.relative(distDir, cjsPath)}`);
	}
}

log(console.log, `[prepare-cjs] Processed ${jsFiles.length} file(s)`);
