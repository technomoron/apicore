import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const testDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(testDir, '../..');
const document = JSON.parse(readFileSync(resolve(packageRoot, 'docs/swagger/openapi.json'), 'utf8')) as {
	info: { version: string };
	paths: Record<string, Record<string, unknown>>;
	components: {
		securitySchemes: Record<string, unknown>;
		schemas: Record<string, unknown>;
	};
};
const packageJson = JSON.parse(readFileSync(resolve(packageRoot, 'package.json'), 'utf8')) as {
	version: string;
};
const operationMethods = new Set(['delete', 'get', 'head', 'options', 'patch', 'post', 'put', 'trace']);

function collectSchemaRefs(value: unknown, references: Set<string>): void {
	if (Array.isArray(value)) {
		value.forEach((entry) => collectSchemaRefs(entry, references));
		return;
	}
	if (!value || typeof value !== 'object') {
		return;
	}
	const object = value as Record<string, unknown>;
	if (typeof object.$ref === 'string' && object.$ref.startsWith('#/components/schemas/')) {
		references.add(object.$ref.slice('#/components/schemas/'.length));
	}
	Object.values(object).forEach((entry) => collectSchemaRefs(entry, references));
}

describe('shipped OpenAPI policy', () => {
	it('matches the package version and documents every reference operation with explicit auth', () => {
		expect(document.info.version).toBe(packageJson.version);
		const declaredSecurity = new Set(Object.keys(document.components.securitySchemes));

		for (const pathItem of Object.values(document.paths)) {
			for (const [method, value] of Object.entries(pathItem)) {
				if (!operationMethods.has(method)) {
					continue;
				}
				const operation = value as {
					description: string;
					security: Array<Record<string, unknown>>;
				};
				expect(operation.description).toMatch(/^Auth: (none|optional|required|strict)/);
				expect(operation.security).toBeDefined();
				for (const security of operation.security) {
					for (const name of Object.keys(security)) {
						expect(declaredSecurity.has(name)).toBe(true);
					}
				}
			}
		}
	});

	it('has no undefined or unused schemas', () => {
		const schemas = document.components.schemas as Record<string, unknown>;
		const references = new Set<string>();
		const expanded = new Set<string>();
		collectSchemaRefs(document.paths, references);

		while ([...references].some((name) => !expanded.has(name))) {
			for (const name of [...references]) {
				if (expanded.has(name)) {
					continue;
				}
				expanded.add(name);
				expect(schemas).toHaveProperty(name);
				collectSchemaRefs(schemas[name], references);
			}
		}

		expect([...references].sort()).toEqual(Object.keys(schemas).sort());
	});

	it('matches current auth and core response schemas', () => {
		const schemas = document.components.schemas;
		const logout = schemas.LogoutRequest as { properties: Record<string, unknown> };
		const oauthRequest = schemas.OAuthTokenRequest as {
			properties: Record<string, unknown> & { grant_type: { enum: string[] } };
		};
		const oauthAuthorize = schemas.OAuthAuthorizeRequest as {
			properties: Record<string, unknown>;
		};
		const oauthResponse = schemas.ApiOAuthTokenRes as { required: string[] };
		const ping = schemas.ApiPingRes as { required: string[] };

		expect(logout.properties).toHaveProperty('refreshToken');
		expect(oauthRequest.properties.grant_type.enum).toEqual([
			'authorization_code',
			'refresh_token'
		]);
		expect(oauthRequest.properties).toHaveProperty('scope');
		expect(oauthAuthorize.properties).toHaveProperty('refreshToken');
		expect(oauthResponse.required).toEqual([
			'access_token',
			'refresh_token',
			'token_type',
			'expires_in',
			'scope',
			'client_id'
		]);
		expect(ping.required).toEqual(expect.arrayContaining(['apiVersion', 'minClientVersion']));
	});

	it('documents the complete TUS operation set', () => {
		expect(document.paths['/api/v1/upload']).toEqual(
			expect.objectContaining({
				options: expect.any(Object),
				post: expect.any(Object)
			})
		);
		expect(document.paths['/api/v1/upload/{uploadId}']).toEqual(
			expect.objectContaining({
				head: expect.any(Object),
				patch: expect.any(Object),
				delete: expect.any(Object)
			})
		);
	});
});
