import { createHmac } from 'node:crypto';

import { afterEach, describe, expect, it } from 'vitest';

import { rawRequest } from '../../src/base/raw-request.js';
import { HmacSigner, RequestSigner } from '../../src/base/request-signing.js';

const realFetch = globalThis.fetch;

afterEach(() => {
	globalThis.fetch = realFetch;
});

describe('rawRequest', () => {
	it('does not expose HMAC secrets and rejects invalid expiry windows', () => {
		const signer = new HmacSigner({ secret: 'do-not-log' });
		expect(JSON.stringify(signer)).not.toContain('do-not-log');
		expect(() => new HmacSigner({ secret: 'shared', maxAge: 0 })).toThrow(/maxAge/);
		expect(() => new HmacSigner({ secret: 'shared', maxAge: Number.NaN })).toThrow(/maxAge/);
	});

	it('supports custom RequestSigner subclasses', async () => {
		class TestSigner extends RequestSigner {
			protected createSignature(content: string): string {
				return createHmac('sha256', 'custom').update(content).digest('hex');
			}
		}
		const signer = new TestSigner();
		const signed = await signer.sign('GET', '/items?a=1', undefined, '100');
		expect(signed.signature).toMatch(/^[a-f\d]{64}$/);
	});

	it('sends raw headers and a custom HMAC header', async () => {
		let captured: { url: string; init: RequestInit } | undefined;
		globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
			captured = { url: String(input), init: init ?? {} };
			return new Response(null, { status: 204 });
		}) as typeof fetch;

		await rawRequest('https://outside.test/items?b=2&a=1', {
			method: 'POST',
			headers: { 'X-Custom': 'value' },
			body: { c: '3' },
			signer: new HmacSigner({ secret: 'shared', signature: 'X-Vendor-Signature', timestamp: 'X-Vendor-Time' })
		});

		const headers = new Headers(captured?.init.headers);
		const timestamp = headers.get('x-vendor-time');
		const content = `POST\n/items\n${timestamp}\na=1&b=2\nc=3`;
		expect(headers.get('x-custom')).toBe('value');
		expect(headers.get('x-vendor-signature')).toBe(createHmac('sha256', 'shared').update(content).digest('hex'));
	});

	it('puts signing values in GET query parameters when requested', async () => {
		let capturedUrl = '';
		globalThis.fetch = (async (input: string | URL | Request) => {
			capturedUrl = String(input);
			return new Response(null, { status: 204 });
		}) as typeof fetch;

		await rawRequest('https://outside.test/items?a=1', {
			signer: new HmacSigner({ secret: 'shared', in: 'parameter', signature: 'sig', timestamp: 'ts' })
		});

		const url = new URL(capturedUrl);
		expect(url.searchParams.get('sig')).toMatch(/^[a-f\d]{64}$/);
		expect(url.searchParams.get('ts')).toMatch(/^\d+$/);
	});
});
