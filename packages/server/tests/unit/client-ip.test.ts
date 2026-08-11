import { describe, it, expect } from 'vitest';

import { TestServer } from '../helpers/test-server';

import type { ApiAuthClass, ApiAuthType, ApiRequest, ExtendedReq, _ApiReply } from '../../src/apicore-server';

type HeaderMap = Record<string, string | string[]>;
type HandleRequest = (
	handler: (apiReq: ApiRequest) => Promise<[number]>,
	auth: { type: ApiAuthType; req: ApiAuthClass }
) => (req: ExtendedReq, res: _ApiReply, next: (error?: unknown) => void) => Promise<void>;

const createRequest = (
	overrides: {
		ip?: string;
		ips?: string[];
		headers?: HeaderMap;
		socket?: { remoteAddress?: string | null };
		connection?: { remoteAddress?: string | null };
	} = {}
): ExtendedReq => {
	const req = {
		headers: overrides.headers ?? {},
		ip: overrides.ip ?? '',
		ips: overrides.ips ?? [],
		socket: { remoteAddress: undefined, ...(overrides.socket ?? {}) },
		connection: overrides.connection ?? undefined
	};

	return req as unknown as ExtendedReq;
};

function createResponseStub(): _ApiReply {
	const res: Partial<_ApiReply> = { locals: {}, headersSent: false };
	res.status = ((code: number) => {
		void code;
		return res as _ApiReply;
	}) as _ApiReply['status'];
	res.json = ((body?: unknown) => {
		void body;
		return;
	}) as _ApiReply['json'];
	res.send = ((body?: unknown) => {
		void body;
		return;
	}) as _ApiReply['send'];
	res.cookie = ((name: string, value: string) => {
		void name;
		void value;
		return;
	}) as _ApiReply['cookie'];
	res.clearCookie = ((name: string) => {
		void name;
		return;
	}) as _ApiReply['clearCookie'];
	return res as _ApiReply;
}

const wrapApiRequest = async (server: TestServer, req: ExtendedReq): Promise<ApiRequest> => {
	let captured: ApiRequest | null = null;
	const handler = (server as unknown as { handle_request: HandleRequest }).handle_request(
		async (apiReq: ApiRequest) => {
			captured = apiReq;
			return [200];
		},
		{ type: 'none', req: 'any' }
	);

	await handler(req, createResponseStub(), () => undefined);

	if (!captured) {
		throw new Error('Failed to capture ApiRequest');
	}
	return captured;
};

describe('ApiServer client IP helpers', () => {
	it('returns the remote address when no proxy headers are present', async () => {
		const server = new TestServer();
		const req = createRequest({
			ip: '198.51.100.10',
			socket: { remoteAddress: '198.51.100.10' }
		});

		const apiReq = await wrapApiRequest(server, req);
		expect(apiReq.getClientIpChain()).toEqual(['198.51.100.10']);
		expect(apiReq.getClientIp()).toBe('198.51.100.10');
	});

	it('ignores forwarded headers by default when trustProxy is not enabled', async () => {
		const server = new TestServer();
		const req = createRequest({
			headers: {
				'x-forwarded-for': '203.0.113.10, 198.51.100.4'
			},
			ips: ['198.51.100.4'],
			ip: '198.51.100.4',
			socket: { remoteAddress: '10.0.0.2' }
		});

		const apiReq = await wrapApiRequest(server, req);
		expect(apiReq.getClientIpChain()).toEqual(['198.51.100.4', '10.0.0.2']);
		expect(apiReq.getClientIp()).toBe('198.51.100.4');
	});

	it('prefers the first forwarded address and deduplicates the chain', async () => {
		const server = new TestServer({ trustProxy: true });
		const req = createRequest({
			headers: {
				'x-forwarded-for': '203.0.113.10, 198.51.100.4 '
			},
			ips: ['198.51.100.4', '10.0.0.2'],
			ip: '198.51.100.4',
			socket: { remoteAddress: '10.0.0.2' }
		});

		const apiReq = await wrapApiRequest(server, req);
		expect(apiReq.getClientIpChain()).toEqual(['203.0.113.10', '198.51.100.4', '10.0.0.2']);
		expect(apiReq.getClientIp()).toBe('203.0.113.10');
	});

	it('parses RFC 7239 forwarded headers and skips loopback when selecting the most likely IP', async () => {
		const server = new TestServer({ trustProxy: true });
		const req = createRequest({
			headers: {
				forwarded: 'for="[2001:db8::1]";proto=https;by=proxy, for=198.51.100.15:443'
			},
			ip: '::ffff:127.0.0.1',
			socket: { remoteAddress: '::ffff:127.0.0.1' }
		});

		const apiReq = await wrapApiRequest(server, req);
		expect(apiReq.getClientIpChain()).toEqual(['2001:db8::1', '198.51.100.15', '127.0.0.1']);
		expect(apiReq.getClientIp()).toBe('2001:db8::1');
	});

	it('uses the proxy-observed client address for numeric trust depth', async () => {
		const server = new TestServer({ trustProxy: 1 });
		const req = createRequest({
			headers: {
				'x-forwarded-for': '1.2.3.4, 203.0.113.77'
			},
			ip: '10.0.0.2',
			socket: { remoteAddress: '10.0.0.2' }
		});

		const apiReq = await wrapApiRequest(server, req);
		expect(apiReq.getClientIpChain()).toEqual(['203.0.113.77', '10.0.0.2']);
		expect(apiReq.getClientIp()).toBe('203.0.113.77');
	});

	it('does not append Fastify-resolved req.ip after the direct proxy address', async () => {
		const server = new TestServer({ trustProxy: 1 });
		const req = createRequest({
			headers: {
				'x-forwarded-for': '1.2.3.4, 203.0.113.77'
			},
			ip: '203.0.113.77',
			socket: { remoteAddress: '10.0.0.2' }
		});

		const apiReq = await wrapApiRequest(server, req);
		expect(apiReq.getClientIpChain()).toEqual(['203.0.113.77', '10.0.0.2']);
		expect(apiReq.getClientIp()).toBe('203.0.113.77');
	});

	it('does not merge competing forwarding header families in numeric mode', async () => {
		const server = new TestServer({ trustProxy: 1 });
		const req = createRequest({
			headers: {
				'x-forwarded-for': '203.0.113.77',
				forwarded: 'for=1.2.3.4',
				'x-real-ip': '5.6.7.8'
			},
			socket: { remoteAddress: '10.0.0.2' }
		});

		const apiReq = await wrapApiRequest(server, req);
		expect(apiReq.getClientIpChain()).toEqual(['203.0.113.77', '10.0.0.2']);
		expect(apiReq.getClientIp()).toBe('203.0.113.77');
	});
});
