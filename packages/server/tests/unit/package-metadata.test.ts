import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const packageJsonPath = fileURLToPath(new URL('../../package.json', import.meta.url));

type PackageJson = {
	dependencies?: Record<string, string>;
	devDependencies?: Record<string, string>;
};

describe('package metadata', () => {
	it('ships jsonwebtoken type declarations to downstream consumers', () => {
		const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as PackageJson;

		expect(packageJson.dependencies?.['@types/jsonwebtoken']).toBeTruthy();
		expect(packageJson.devDependencies?.['@types/jsonwebtoken']).toBeFalsy();
	});
});
