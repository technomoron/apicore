import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import request from 'supertest';
import { describe, it, expect } from 'vitest';

const __dirname = dirname(fileURLToPath(import.meta.url));

import ApiServer from '../../src/apicore-server';
import AuthModule from '../../src/auth-api/auth-module';
import { MemAuthStore } from '../../src/auth-api/mem-auth-store';
import { HmacSigner } from '../../src/base/request-signing';
import { MemoryTusUploadStore } from '../../src/upload/memory';
import { TusUploadModule } from '../../src/upload/tus-module';
import { createServer } from '../helpers/test-server';

describe('Swagger endpoint', () => {
	it('declares request signing and applies it to signed runtime operations', async () => {
		const server = createServer({
			swaggerEnabled: true,
			signer: new HmacSigner({ secret: 'shared' })
		});
		server.api(new AuthModule());

		const response = await request(server.app).get('/api/swagger');
		const scheme = response.body.components?.securitySchemes?.requestSignature;
		const loginSecurity = response.body.paths?.['/api/auth/v1/login']?.post?.security;

		expect(scheme).toMatchObject({ type: 'apiKey', in: 'header', name: 'X-ApiCore-Signature' });
		expect(loginSecurity).toEqual([{ requestSignature: [] }]);
	});

	it('returns a 404 under the apiBasePath when swagger is disabled', async () => {
		const server = createServer();

		const response = await request(server.app).get('/api/swagger');

		expect(response.status).toBe(404);
		expect(response.body).toEqual({
			success: false,
			code: 404,
			message: 'No such endpoint: GET /api/swagger',
			data: null,
			errors: {}
		});
	});

	it('serves the OpenAPI document at the default swagger path when enabled', async () => {
		const server = createServer({ swaggerEnabled: true });
		const packageJson = JSON.parse(readFileSync(resolve(__dirname, '../../package.json'), 'utf8')) as {
			version: string;
		};

		const response = await request(server.app).get('/api/swagger');

		expect(response.status).toBe(200);
		expect(response.body.openapi).toBe('3.1.0');
		expect(response.body.info?.title).toBe('ApiCore Server');
		expect(response.body.info?.version).toBe(packageJson.version);
		expect(Object.keys(response.body.paths)).toEqual(
			expect.arrayContaining(['/api/v1/ping', '/api/v1/uploads/purge'])
		);
		expect(response.body.paths).not.toHaveProperty('/api/auth/v1/login');
	});

	it('serves the OpenAPI document at a custom swagger path', async () => {
		const server = createServer({ swaggerPath: '/docs/openapi' });

		const response = await request(server.app).get('/docs/openapi');

		expect(response.status).toBe(200);
		expect(response.body.openapi).toBe('3.1.0');
	});

	it('documents impersonation-end metadata as query parameters instead of a request body', async () => {
		const server = createServer({ swaggerEnabled: true });
		server.api(new AuthModule());

		const response = await request(server.app).get('/api/swagger');

		expect(response.status).toBe(200);
		const operation = response.body.paths?.['/api/auth/v1/impersonations']?.delete;
		expect(operation?.requestBody).toBeUndefined();
		expect(Array.isArray(operation?.parameters)).toBe(true);
		expect(
			operation.parameters.some(
				(param: { name?: string; in?: string }) => param.name === 'label' && param.in === 'query'
			)
		).toBe(true);
		expect(
			operation.parameters.some(
				(param: { name?: string; in?: string }) => param.name === 'browser' && param.in === 'query'
			)
		).toBe(true);
	});

	it('documents the strict-admin upload purge endpoint and its response', async () => {
		const server = createServer({ swaggerEnabled: true });

		const response = await request(server.app).get('/api/swagger');
		const operation = response.body.paths?.['/api/v1/uploads/purge']?.post;

		expect(response.status).toBe(200);
		expect(operation?.description).toMatch(/^Auth: strict/);
		expect(operation?.security).toEqual(
			expect.arrayContaining([{ accessTokenBearer: [] }, { accessTokenCookie: [] }, { apiKeyBearer: [] }])
		);
		expect(operation?.responses).toHaveProperty('200');
		expect(operation?.responses).toHaveProperty('401');
		expect(operation?.responses).toHaveProperty('403');
		expect(
			operation?.responses?.['200']?.content?.['application/json']?.schema?.allOf?.[1]?.properties?.data?.$ref
		).toBe('#/components/schemas/UploadPurgeSummary');
	});

	it('uses configured core and auth paths and omits optional routes that were not mounted', async () => {
		const server = createServer({
			apiBasePath: '/custom',
			swaggerEnabled: true
		});
		server.api(new AuthModule({ namespace: '/accounts' }));

		const response = await request(server.app).get('/custom/swagger');

		expect(response.status).toBe(200);
		expect(response.body.paths).toHaveProperty('/custom/v1/ping');
		expect(response.body.paths).toHaveProperty('/custom/accounts/v1/login');
		expect(response.body.paths).not.toHaveProperty('/api/v1/ping');
		expect(response.body.paths).not.toHaveProperty('/api/auth/v1/login');
		expect(response.body.paths).not.toHaveProperty('/custom/accounts/v1/passkeys/challenge');
		expect(response.body.paths).not.toHaveProperty('/custom/accounts/v1/oauth2/token');
		expect(response.body.components.schemas).not.toHaveProperty('PasskeyChallengeRequest');
		expect(response.body.components.schemas).not.toHaveProperty('OAuthTokenRequest');
	});

	it('includes passkey and OAuth operations only when their services are mounted', async () => {
		const store = new MemAuthStore({
			passkeys: {
				enabled: true,
				rpId: 'example.test',
				origins: ['https://example.test']
			}
		});
		await store.initialise();
		try {
			const server = new ApiServer({
				accessSecret: 'access-secret',
				refreshSecret: 'refresh-secret',
				swaggerEnabled: true
			})
				.authStorage(store)
				.api(new AuthModule());

			const response = await request(server.app).get('/api/swagger');

			expect(response.status).toBe(200);
			expect(response.body.paths).toHaveProperty('/api/auth/v1/passkeys/challenge');
			expect(response.body.paths).toHaveProperty('/api/auth/v1/passkeys/verify');
			expect(response.body.paths).toHaveProperty('/api/auth/v1/oauth2/authorize');
			expect(response.body.paths).toHaveProperty('/api/auth/v1/oauth2/token');
			expect(response.body.paths).not.toHaveProperty('/api/auth/v1/oauth2/{provider}/start');
			expect(response.body.paths).not.toHaveProperty('/api/auth/v1/oauth2/{provider}/callback');
		} finally {
			await store.close();
		}
	});

	it('documents a mounted TUS path with its configured authentication policy', async () => {
		const server = createServer({ swaggerEnabled: true });
		server.api(
			new TusUploadModule({
				auth: { type: 'none', req: 'any' },
				basePath: '/uploads/resumable',
				store: new MemoryTusUploadStore()
			})
		);

		const response = await request(server.app).get('/api/swagger');
		const collection = response.body.paths?.['/uploads/resumable'];
		const upload = response.body.paths?.['/uploads/resumable/{uploadId}'];

		expect(response.status).toBe(200);
		expect(response.body.paths).not.toHaveProperty('/api/v1/upload');
		expect(collection).toHaveProperty('options');
		expect(collection).toHaveProperty('post');
		expect(upload).toHaveProperty('head');
		expect(upload).toHaveProperty('patch');
		expect(upload).toHaveProperty('delete');
		expect(collection.post.description).toMatch(/^Auth: none/);
		expect(collection.post.security).toEqual([]);
		expect(upload.patch.description).toMatch(/^Auth: none/);
		expect(upload.patch.security).toEqual([]);
	});
});
