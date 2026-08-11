import request from 'supertest';
import { describe, expect, it } from 'vitest';

import { ApiModule, type ApiRoute } from '../../src/api-module.js';
import {
	HmacSigner,
	canonicalRequestParameters,
	requestSignature,
	requestSigningContent
} from '../../src/base/request-signing.js';
import { createServer, TestServer } from '../helpers/test-server';

const secret = 'shared-request-secret';

function signedHeaders(
	method: string,
	url: string,
	body?: unknown,
	timestamp = Math.floor(Date.now() / 1000),
	sharedSecret = secret
) {
	const timestampText = String(timestamp);
	return {
		'X-ApiCore-Timestamp': timestampText,
		'X-ApiCore-Signature': requestSignature(sharedSecret, requestSigningContent(method, url, timestampText, body))
	};
}

class SplitSigningModule extends ApiModule<TestServer> {
	constructor(private readonly strongSigner: HmacSigner) {
		super({ namespace: '/split-signing' });
	}

	public override defineRoutes(): ApiRoute[] {
		const handler = async (): Promise<[number, { ok: boolean }]> => [200, { ok: true }];
		return [
			{ method: 'get', path: '/default', auth: { type: 'none', req: 'any' }, handler },
			{ method: 'get', path: '/strong', auth: { type: 'none', req: 'any' }, signer: this.strongSigner, handler },
			{ method: 'get', path: '/open', auth: { type: 'none', req: 'any' }, signer: false, handler },
			{
				method: 'get',
				path: '/get-body',
				auth: { type: 'none', req: 'any' },
				handler: async ({ req }) => [200, { body: req.body }]
			},
			{
				method: 'patch',
				path: '/inspect',
				auth: { type: 'none', req: 'any' },
				handler: async ({ req }) => [200, { query: req.query, body: req.body }]
			}
		];
	}
}

describe('shared-secret request signing', () => {
	it('sorts query and POST parameters by name and content', () => {
		expect(
			canonicalRequestParameters('/api/example/patchable?z=9&a=3&a=1', {
				z: '2',
				a: ['4', '2']
			})
		).toEqual({ query: 'a=1&a=3&z=9', body: 'a=2&a=4&z=2' });
	});

	it('accepts a valid signature regardless of parameter order', async () => {
		const server = createServer({ signer: new HmacSigner({ secret }) });
		const url = '/api/example/patchable?z=9&a=3&a=1';
		const body = { z: '2', a: '2' };
		const response = await request(server.app)
			.patch(url)
			.set(signedHeaders('PATCH', url, body))
			.send(body);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ patched: true, body });
	});

	it('rejects missing, changed, and expired signatures', async () => {
		const server = createServer({ signer: new HmacSigner({ secret }) });
		const url = '/api/example/patchable?a=1';
		const body = { value: 'original' };

		const missing = await request(server.app).patch(url).send(body);
		const changed = await request(server.app)
			.patch(url)
			.set(signedHeaders('PATCH', url, body))
			.send({ value: 'changed' });
		const expired = await request(server.app)
			.patch(url)
			.set(signedHeaders('PATCH', url, body, Math.floor(Date.now() / 1000) - 301))
			.send(body);

		expect(missing.status).toBe(401);
		expect(changed.status).toBe(401);
		expect(expired.status).toBe(401);
	});

	it('accepts and removes custom signature parameters', async () => {
		const signatureName = 'sig';
		const timestampName = 'ts';
		const signer = new HmacSigner({ secret, in: 'parameter', signature: signatureName, timestamp: timestampName });
		const server = new TestServer();
		server.api(new SplitSigningModule(signer), { signer });
		const url = `/api/split-signing/inspect?a=1&${signatureName}=evil&${timestampName}=evil`;
		const timestamp = String(Math.floor(Date.now() / 1000));
		const body = { value: 'signed' };
		const signature = requestSignature(
			secret,
			requestSigningContent('PATCH', url, timestamp, body, new Set([signatureName, timestampName]))
		);
		const response = await request(server.app)
			.patch(url)
			.send({ ...body, [timestampName]: timestamp, [signatureName]: signature });

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ query: { a: '1' }, body });
	});

	it('removes credential-named parameters when credentials use headers', async () => {
		const signer = new HmacSigner({ secret, signature: 'signature', timestamp: 'timestamp' });
		const server = new TestServer();
		server.api(new SplitSigningModule(signer), { signer });
		const url = '/api/split-signing/inspect?signature=evil&timestamp=evil&a=1';
		const body = { signature: 'evil', timestamp: 'evil', value: 'signed' };
		const signed = await signer.sign('PATCH', url, body);
		const response = await request(server.app)
			.patch(url)
			.set('signature', signed.signature)
			.set('timestamp', signed.timestamp)
			.send(body);

		expect(response.status).toBe(200);
		expect(response.body.data).toEqual({ query: { a: '1' }, body: { value: 'signed' } });
	});

	it('supports server defaults, api overrides, route overrides, and unsigned exceptions', async () => {
		const lowRisk = new HmacSigner({ secret: 'low-risk' });
		const strong = new HmacSigner({ secret: 'strong' });
		const server = new TestServer();
		server.api(new SplitSigningModule(strong), { signer: lowRisk });

		const defaultUrl = '/api/split-signing/default';
		const strongUrl = '/api/split-signing/strong';
		const defaultResponse = await request(server.app)
			.get(defaultUrl)
			.set(signedHeaders('GET', defaultUrl, undefined, Math.floor(Date.now() / 1000), 'low-risk'));
		const wrongStrong = await request(server.app)
			.get(strongUrl)
			.set(signedHeaders('GET', strongUrl, undefined, Math.floor(Date.now() / 1000), 'low-risk'));
		const rightStrong = await request(server.app)
			.get(strongUrl)
			.set(signedHeaders('GET', strongUrl, undefined, Math.floor(Date.now() / 1000), 'strong'));
		const openResponse = await request(server.app).get('/api/split-signing/open');

		expect(defaultResponse.status).toBe(200);
		expect(wrongStrong.status).toBe(401);
		expect(rightStrong.status).toBe(200);
		expect(openResponse.status).toBe(200);
	});

	it('rejects a GET body that was not included in the signature', async () => {
		const signer = new HmacSigner({ secret });
		const server = new TestServer();
		server.api(new SplitSigningModule(signer), { signer });
		const url = '/api/split-signing/get-body';
		const response = await request(server.app).get(url).set(signedHeaders('GET', url)).send({ injected: true });

		expect(response.status).toBe(401);
	});

	it('binds parameters to query or body location', async () => {
		const signer = new HmacSigner({ secret });
		const server = new TestServer();
		server.api(new SplitSigningModule(signer), { signer });
		const signedUrl = '/api/split-signing/inspect';
		const movedUrl = `${signedUrl}?value=original`;
		const response = await request(server.app)
			.patch(movedUrl)
			.set(signedHeaders('PATCH', signedUrl, { value: 'original' }))
			.send({});

		expect(response.status).toBe(401);
	});

	it('does not apply the server default to preflight, ping, or unmatched routes', async () => {
		const server = createServer({ signer: new HmacSigner({ secret }) });
		const preflight = await request(server.app)
			.options('/api/example/public')
			.set('Origin', 'http://allowed.test')
			.set('Access-Control-Request-Method', 'GET');
		const ping = await request(server.app).get('/api/v1/ping');
		const missing = await request(server.app).get('/api/not-found');

		expect(preflight.status).toBe(200);
		expect(ping.status).toBe(200);
		expect(missing.status).toBe(404);
	});
});
