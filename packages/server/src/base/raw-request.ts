import type { RequestSigner } from './request-signing.js';

export interface RawRequestOptions extends Omit<RequestInit, 'body' | 'headers' | 'method'> {
	method?: string;
	headers?: HeadersInit;
	body?: BodyInit | Record<string, unknown> | null;
	signer?: RequestSigner;
}

function isBodyInit(body: unknown): body is BodyInit {
	return (
		typeof body === 'string' ||
		body instanceof URLSearchParams ||
		body instanceof FormData ||
		body instanceof Blob ||
		body instanceof ArrayBuffer ||
		ArrayBuffer.isView(body)
	);
}

function prepareBody(body: RawRequestOptions['body'], headers: Headers): BodyInit | null | undefined {
	if (body === undefined || body === null || isBodyInit(body)) return body;
	if (!headers.has('content-type')) headers.set('content-type', 'application/json');
	return JSON.stringify(body);
}

/** Send an outbound HTTP request with arbitrary headers and optional signing. */
export async function rawRequest(input: string | URL, options: RawRequestOptions = {}): Promise<Response> {
	const method = (options.method ?? 'GET').toUpperCase();
	const headers = new Headers(options.headers);
	let url = new URL(input);
	let body = prepareBody(options.body, headers);
	if (options.signer) {
		body = await options.signer.apply(url, method, body, headers);
		if (options.signer.in === 'parameter' && method !== 'GET' && method !== 'DELETE') {
			if (!headers.has('content-type') && typeof body === 'string')
				headers.set('content-type', 'application/json');
		}
	}
	const { signer: _signer, ...init } = options;
	void _signer;
	return fetch(url, { ...init, method, headers, body });
}
