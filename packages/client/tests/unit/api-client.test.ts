import { createHmac } from 'node:crypto';

import { HmacSigner as ServerHmacSigner } from '@technomoron/apicore-server';
import { test, expect, vi } from 'vitest';

import { ApiClient, HmacSigner } from '../../src/index.js';

import type { ApiClientConfig } from '../../src/index.js';

function makeResponse({
	ok,
	status,
	jsonData,
	headers
}: {
	ok?: boolean;
	status?: number;
	jsonData?: object;
	headers?: Record<string, string>;
} = {}) {
	return {
		ok: ok ?? true,
		status: status ?? 200,
		headers: new Headers(headers ?? {}),
		async json() {
			return (
				jsonData ?? {
					success: true,
					code: status ?? 200,
					message: 'OK',
					data: null,
					errors: {}
				}
			);
		}
	};
}

function headersToObject(headers: Headers) {
	const obj: Record<string, string> = {};
	for (const [k, v] of headers.entries()) obj[k.toLowerCase()] = v;
	return obj;
}

test('ApiClient strips trailing slash from apiUrl and builds url correctly', async () => {
	const realFetch = globalThis.fetch;
	const calls: { input: unknown; init: RequestInit }[] = [];
	(globalThis as unknown as { fetch: unknown }).fetch = async (input: unknown, init: RequestInit) => {
		calls.push({ input, init });
		return makeResponse({
			ok: true,
			status: 200,
			jsonData: {
				success: true,
				code: 200,
				message: 'OK',
				data: { v: 1 },
				errors: {}
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test/', {
			enableTokens: false
		});
		const r = await client.get('/api/v1/ping');
		expect(r.success).toBe(true);
		expect(String(calls[0].input)).toBe('https://example.test/api/v1/ping');
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('ApiClient configure/getConfig roundtrip', () => {
	const client = new ApiClient('https://example.test', {
		apiKey: 'k1',
		timeout: 1,
		maxRetries: 2,
		debug: true
	});
	const initialConfig: ApiClientConfig = client.getConfig();
	expect(initialConfig).toStrictEqual({
		apiKey: '***', // raw key is masked; presence can still be checked
		timeout: 1,
		maxRetries: 2,
		debug: true,
		enableTokens: true,
		authBasePath: '/api/auth/v1',
		apiBasePath: '/api'
	});

	client.configure({
		apiKey: null,
		timeout: 10,
		maxRetries: 0,
		debug: false,
		enableTokens: false
	});
	expect(client.getConfig()).toStrictEqual({
		apiKey: null,
		timeout: 10,
		maxRetries: 0,
		debug: false,
		enableTokens: false,
		authBasePath: '/api/auth/v1',
		apiBasePath: '/api'
	});
});

test('ping uses the configured core API base path', async () => {
	const realFetch = globalThis.fetch;
	let requestUrl = '';
	(globalThis as unknown as { fetch: unknown }).fetch = async (input: unknown) => {
		requestUrl = String(input);
		return makeResponse();
	};

	try {
		const client = new ApiClient('https://example.test', {
			apiBasePath: 'custom/',
			enableTokens: false
		});
		const response = await client.ping();

		expect(response.success).toBe(true);
		expect(requestUrl).toBe('https://example.test/custom/v1/ping');
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('login stores tokens and subsequent requests use access token when tokens enabled', async () => {
	const realFetch = globalThis.fetch;
	const calls: {
		url: string;
		init: RequestInit;
		hdrs: Record<string, string>;
	}[] = [];
	(globalThis as unknown as { fetch: unknown }).fetch = async (input: unknown, init: RequestInit) => {
		const url = String(input);
		const hdrs = headersToObject(new Headers(init.headers as HeadersInit));
		calls.push({ url, init, hdrs });

		if (url.endsWith('/api/auth/v1/login')) {
			expect(init.method).toBe('POST');
			expect(init.credentials).toBe('include');
			expect(hdrs['content-type']).toBe('application/json');
			return makeResponse({
				ok: true,
				status: 200,
				jsonData: {
					success: true,
					code: 200,
					message: 'Login ok',
					data: {
						accessToken: 'a1',
						refreshToken: 'r1',
						user: { id: 1 }
					},
					errors: {}
				}
			});
		}

		expect(hdrs['authorization']).toBe('Bearer a1');
		return makeResponse({
			ok: true,
			status: 200,
			jsonData: {
				success: true,
				code: 200,
				message: 'OK',
				data: { pong: true },
				errors: {}
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test');
		const login = await client.login('u', 'p', 'd', 'f');
		expect(login.success).toBe(true);

		const r = await client.get('/api/v1/ping');
		expect(r.success).toBe(true);
		expect(calls.length).toBe(2);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('login failure returns an error ApiResponse with status and errors', async () => {
	const realFetch = globalThis.fetch;
	(globalThis as unknown as { fetch: unknown }).fetch = async (input: unknown) => {
		const url = String(input);
		expect(url.endsWith('/api/auth/v1/login')).toBe(true);
		return makeResponse({
			ok: false,
			status: 401,
			jsonData: {
				success: false,
				code: 401,
				message: 'bad creds',
				data: null,
				errors: { login: 'nope' }
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test');
		const r = await client.login('u', 'p', 'd', 'f');
		expect(r.success).toBe(false);
		expect(r.code).toBe(401);
		expect(r.message).toBe('bad creds');
		expect(r.errors).toStrictEqual({ login: 'nope' });
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('apiKey wins over access token for Authorization header', async () => {
	const realFetch = globalThis.fetch;
	(globalThis as unknown as { fetch: unknown }).fetch = async (_input: unknown, init: RequestInit) => {
		const hdrs = headersToObject(new Headers(init.headers as HeadersInit));
		expect(hdrs['authorization']).toBe('Bearer api-key-1');
		return makeResponse({
			ok: true,
			status: 200,
			jsonData: {
				success: true,
				code: 200,
				message: 'OK',
				data: { ok: true },
				errors: {}
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test', {
			apiKey: 'api-key-1'
		});
		client.set_access_token('access-should-not-be-used');
		const r = await client.get('/api/v1/ping');
		expect(r.success).toBe(true);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('tokens disabled: access token is not attached', async () => {
	const realFetch = globalThis.fetch;
	(globalThis as unknown as { fetch: unknown }).fetch = async (_input: unknown, init: RequestInit) => {
		const hdrs = headersToObject(new Headers(init.headers as HeadersInit));
		expect('authorization' in hdrs).toBe(false);
		return makeResponse({
			ok: true,
			status: 200,
			jsonData: {
				success: true,
				code: 200,
				message: 'OK',
				data: { ok: true },
				errors: {}
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test', {
			enableTokens: false
		});
		client.set_access_token('a1');
		const r = await client.get('/api/v1/ping');
		expect(r.success).toBe(true);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('401 with no refresh token does not attempt refresh', async () => {
	const realFetch = globalThis.fetch;
	let callCount = 0;

	(globalThis as unknown as { fetch: unknown }).fetch = async () => {
		callCount++;
		return makeResponse({
			ok: false,
			status: 401,
			jsonData: {
				success: false,
				code: 401,
				message: 'Unauthorized',
				data: null,
				errors: {}
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test', { maxRetries: 0 });
		const r = await client.get('/api/v1/test');
		expect(r.success).toBe(false);
		expect(r.code).toBe(401);
		expect(callCount).toBe(1);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('debug logging redacts auth headers and token-like body fields', async () => {
	const realFetch = globalThis.fetch;
	const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
	(globalThis as unknown as { fetch: unknown }).fetch = async (input: unknown) => {
		void input;
		return makeResponse({
			ok: true,
			status: 200,
			jsonData: {
				success: true,
				code: 200,
				message: 'OK',
				data: { ok: true },
				errors: {}
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test', {
			apiKey: 'api-secret',
			debug: true,
			enableTokens: false
		});
		const response = await client.post('/api/v1/secure', {
			refreshToken: 'refresh-secret',
			password: 'pw',
			nested: { token: 'nested-secret' }
		});
		expect(response.success).toBe(true);

		const headersCall = logSpy.mock.calls.find(([label]) => label === '[safeFetch] Headers:');
		expect(headersCall?.[1]).toMatchObject({ authorization: '[REDACTED]' });

		const bodyCall = logSpy.mock.calls.find(([label]) => label === 'Request body:');
		expect(bodyCall?.[1]).toEqual({
			refreshToken: '[REDACTED]',
			password: '[REDACTED]',
			nested: { token: '[REDACTED]' }
		});
	} finally {
		logSpy.mockRestore();
		globalThis.fetch = realFetch;
	}
});

test('request with files uses FormData and does not force Content-Type header', async () => {
	const realFetch = globalThis.fetch;
	(globalThis as unknown as { fetch: unknown }).fetch = async (_input: unknown, init: RequestInit) => {
		const hdrs = headersToObject(new Headers(init.headers as HeadersInit));
		expect('content-type' in hdrs).toBe(false);
		expect(init.method).toBe('POST');
		expect(init.credentials).toBe('include');

		expect(init.body instanceof FormData).toBe(true);
		const entries = Array.from((init.body as FormData).entries());

		expect(entries.some(([k, v]) => k === 'a' && v === '1')).toBe(true);
		expect(entries.some(([k, v]) => k === 'obj' && v === '{"x":2}')).toBe(true);
		expect(entries.some(([k, v]) => k === 'f1' && typeof v === 'object')).toBe(true);
		expect(entries.some(([k, v]) => k === 'files' && typeof v === 'object')).toBe(true);

		return makeResponse({
			ok: true,
			status: 200,
			jsonData: {
				success: true,
				code: 200,
				message: 'OK',
				data: { uploaded: true },
				errors: {}
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test', {
			enableTokens: false
		});
		const r = await client.post('/api/v1/upload', { a: 1, obj: { x: 2 } }, [
			['f1', new Blob(['abc'])],
			new Blob(['def'])
		]);
		expect(r.success).toBe(true);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('401 triggers refresh once when refresh token exists, then retries original request with new access token', async () => {
	const realFetch = globalThis.fetch;
	let testCallCount = 0;
	let refreshCallCount = 0;

	(globalThis as unknown as { fetch: unknown }).fetch = async (input: unknown, init: RequestInit) => {
		const url = String(input);
		const hdrs = headersToObject(new Headers(init.headers as HeadersInit));

		if (url.endsWith('/api/auth/v1/refresh')) {
			refreshCallCount++;
			expect(hdrs['content-type']).toBe('application/json');
			return makeResponse({
				ok: true,
				status: 200,
				jsonData: {
					success: true,
					code: 200,
					message: 'refreshed',
					data: {
						accessToken: 'new-access',
						refreshToken: 'new-refresh'
					},
					errors: {}
				}
			});
		}

		if (url.endsWith('/api/v1/test')) {
			testCallCount++;
			if (testCallCount === 1) {
				expect(hdrs['authorization']).toBe('Bearer old-access');
				return makeResponse({
					ok: false,
					status: 401,
					jsonData: {
						success: false,
						code: 401,
						message: 'Unauthorized',
						data: null,
						errors: {}
					}
				});
			}

			expect(hdrs['authorization']).toBe('Bearer new-access');
			return makeResponse({
				ok: true,
				status: 200,
				jsonData: {
					success: true,
					code: 200,
					message: 'OK',
					data: { v: 123 },
					errors: {}
				}
			});
		}

		throw new Error(`Unexpected URL: ${url}`);
	};

	try {
		const client = new ApiClient('https://example.test');
		client.set_access_token('old-access');
		client.set_refresh_token('old-refresh');

		const r = await client.get('/api/v1/test');
		expect(r.success).toBe(true);
		expect(testCallCount).toBe(2);
		expect(refreshCallCount).toBe(1);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('auth refresh retries the request when timeout retries are disabled', async () => {
	const realFetch = globalThis.fetch;
	let requestCount = 0;
	let refreshCount = 0;

	(globalThis as unknown as { fetch: unknown }).fetch = async (input: unknown) => {
		const url = String(input);
		if (url.endsWith('/api/auth/v1/refresh')) {
			refreshCount += 1;
			return makeResponse({
				ok: true,
				status: 200,
				jsonData: {
					success: true,
					code: 200,
					message: 'refreshed',
					data: {
						accessToken: 'new-access',
						refreshToken: 'new-refresh'
					},
					errors: {}
				}
			});
		}
		requestCount += 1;
		return makeResponse({
			ok: requestCount > 1,
			status: requestCount > 1 ? 200 : 401,
			jsonData:
				requestCount > 1
					? {
							success: true,
							code: 200,
							message: 'OK',
							data: { ok: true },
							errors: {}
						}
					: {
							success: false,
							code: 401,
							message: 'Unauthorized',
							data: null,
							errors: {}
						}
		});
	};

	try {
		const client = new ApiClient('https://example.test', { maxRetries: 0 });
		client.set_access_token('old-access');
		client.set_refresh_token('old-refresh');

		const response = await client.get('/api/v1/test');

		expect(response.success).toBe(true);
		expect(requestCount).toBe(2);
		expect(refreshCount).toBe(1);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('refresh failure returns an error and does not retry refresh', async () => {
	const realFetch = globalThis.fetch;
	let testCallCount = 0;
	let refreshCallCount = 0;

	(globalThis as unknown as { fetch: unknown }).fetch = async (input: unknown) => {
		const url = String(input);

		if (url.endsWith('/api/auth/v1/refresh')) {
			refreshCallCount++;
			return makeResponse({
				ok: false,
				status: 401,
				jsonData: {
					success: false,
					code: 401,
					message: 'refresh bad',
					data: null,
					errors: {}
				}
			});
		}

		if (url.endsWith('/api/v1/test')) {
			testCallCount++;
			return makeResponse({
				ok: false,
				status: 401,
				jsonData: {
					success: false,
					code: 401,
					message: 'Unauthorized',
					data: null,
					errors: {}
				}
			});
		}

		throw new Error(`Unexpected URL: ${url}`);
	};

	try {
		const client = new ApiClient('https://example.test', { maxRetries: 0 });
		client.set_access_token('old-access');
		client.set_refresh_token('old-refresh');

		const r = await client.get('/api/v1/test');
		expect(r.success).toBe(false);
		expect(r.code).toBe(401);
		expect(r.message).toBe('refresh bad');
		expect(testCallCount).toBe(1);
		expect(refreshCallCount).toBe(1);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('401 after refresh does not attempt a second refresh', async () => {
	const realFetch = globalThis.fetch;
	let refreshCallCount = 0;

	(globalThis as unknown as { fetch: unknown }).fetch = async (input: unknown) => {
		const url = String(input);
		if (url.endsWith('/api/auth/v1/refresh')) {
			refreshCallCount++;
			return makeResponse({
				ok: true,
				status: 200,
				jsonData: {
					success: true,
					code: 200,
					message: 'refreshed',
					data: {
						accessToken: 'new-access',
						refreshToken: 'new-refresh'
					},
					errors: {}
				}
			});
		}

		if (url.endsWith('/api/v1/test')) {
			return makeResponse({
				ok: false,
				status: 401,
				jsonData: {
					success: false,
					code: 401,
					message: 'Unauthorized',
					data: null,
					errors: {}
				}
			});
		}

		throw new Error(`Unexpected URL: ${url}`);
	};

	try {
		const client = new ApiClient('https://example.test');
		client.set_access_token('old-access');
		client.set_refresh_token('old-refresh');

		const r = await client.get('/api/v1/test');
		expect(r.success).toBe(false);
		expect(r.code).toBe(401);
		expect(refreshCallCount).toBe(1);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('timeout (AbortError) retries up to maxRetries', async () => {
	const realFetch = globalThis.fetch;
	let callCount = 0;

	(globalThis as unknown as { fetch: unknown }).fetch = async () => {
		callCount++;
		if (callCount === 1) {
			throw new DOMException('The operation was aborted', 'AbortError');
		}
		return makeResponse({
			ok: true,
			status: 200,
			jsonData: {
				success: true,
				code: 200,
				message: 'OK',
				data: { ok: true },
				errors: {}
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test', {
			maxRetries: 1,
			enableTokens: false
		});
		const r = await client.get('/api/v1/test');
		expect(r.success).toBe(true);
		expect(callCount).toBe(2);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('circular JSON body returns ApiResponse error with code 400', async () => {
	const realFetch = globalThis.fetch;
	(globalThis as unknown as { fetch: unknown }).fetch = async () => {
		throw new Error('fetch should not be called when body serialization fails');
	};

	try {
		const client = new ApiClient('https://example.test', {
			enableTokens: false
		});
		const body: Record<string, unknown> = {};
		body['self'] = body;
		const r = await client.post('/api/v1/test', body);
		expect(r.success).toBe(false);
		expect(r.code).toBe(400);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('network error codes are mapped to user-friendly messages and HTTP-ish codes (Node branch)', async () => {
	const realFetch = globalThis.fetch;
	(globalThis as unknown as { fetch: unknown }).fetch = async () => {
		const err = new Error('connect ECONNREFUSED 127.0.0.1');
		(err as unknown as { code: string }).code = 'ECONNREFUSED';
		throw err;
	};

	try {
		const client = new ApiClient('https://example.test', {
			enableTokens: false,
			maxRetries: 0
		});
		const r = await client.get('/api/v1/test');
		expect(r.success).toBe(false);
		expect(r.code).toBe(503);
		expect(r.message).toMatch(/Fetch failed: Connection refused by server/);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('browser fetch failure message (browser branch)', async () => {
	const realFetch = globalThis.fetch;
	const realWindow = (globalThis as unknown as { window?: unknown }).window;

	(globalThis as unknown as { window: unknown }).window = { document: {} };
	(globalThis as unknown as { fetch: unknown }).fetch = async () => {
		throw new TypeError('Failed to fetch');
	};

	try {
		const client = new ApiClient('https://example.test', {
			enableTokens: false,
			maxRetries: 0
		});
		const r = await client.get('/api/v1/test');
		expect(r.success).toBe(false);
		expect(r.code).toBe(503);
		expect(r.message).toMatch(/Possible CORS issue or server unreachable/);
	} finally {
		globalThis.fetch = realFetch;
		(globalThis as unknown as { window: unknown }).window = realWindow;
	}
});

test('HTTP ok but payload.success=false returns an error response', async () => {
	const realFetch = globalThis.fetch;
	(globalThis as unknown as { fetch: unknown }).fetch = async () => {
		return makeResponse({
			ok: true,
			status: 200,
			jsonData: {
				success: false,
				code: 400,
				message: 'Nope',
				data: null,
				errors: { a: 'b' }
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test', {
			enableTokens: false
		});
		const r = await client.get('/api/v1/test');
		expect(r.success).toBe(false);
		expect(r.code).toBe(400);
		expect(r.message).toBe('Nope');
		expect(r.errors).toStrictEqual({ a: 'b' });
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('apiKey auth failures do not attempt token refresh', async () => {
	const realFetch = globalThis.fetch;
	const calls: { url: string; init: RequestInit }[] = [];

	(globalThis as unknown as { fetch: unknown }).fetch = async (input: unknown, init: RequestInit) => {
		calls.push({ url: String(input), init });
		return makeResponse({
			ok: false,
			status: 401,
			jsonData: {
				success: false,
				code: 401,
				message: 'Unauthorized',
				data: null,
				errors: {}
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test', {
			apiKey: 'k',
			maxRetries: 0
		});
		client.set_refresh_token('should-not-be-used');
		const r = await client.get('/api/v1/test');
		expect(r.success).toBe(false);
		expect(r.code).toBe(401);
		expect(calls.length).toBe(1);
		expect(calls.some((c) => c.url.endsWith('/api/auth/v1/refresh'))).toBe(false);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('logout success clears stored tokens', async () => {
	const realFetch = globalThis.fetch;
	let didLogout = false;

	(globalThis as unknown as { fetch: unknown }).fetch = async (input: unknown, init: RequestInit) => {
		const url = String(input);

		if (url.endsWith('/api/auth/v1/logout')) {
			didLogout = true;
			expect(init.method).toBe('POST');
			expect(init.credentials).toBe('include');
			return makeResponse({
				ok: true,
				status: 200,
				jsonData: {
					success: true,
					code: 200,
					message: 'OK',
					data: { revoked: 1 },
					errors: {}
				}
			});
		}

		const hdrs = headersToObject(new Headers(init.headers as HeadersInit));
		expect('authorization' in hdrs).toBe(false);
		return makeResponse({
			ok: true,
			status: 200,
			jsonData: {
				success: true,
				code: 200,
				message: 'OK',
				data: { ok: true },
				errors: {}
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test');
		client.set_access_token('a1');
		client.set_refresh_token('r1');

		const r = await client.logout();
		expect(r.success).toBe(true);
		expect(didLogout).toBe(true);
		expect(client.get_access_token()).toBe(null);
		expect(client.get_refresh_token()).toBe(null);

		const after = await client.get('/api/v1/test');
		expect(after.success).toBe(true);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('logout failure still clears stored tokens', async () => {
	const realFetch = globalThis.fetch;
	(globalThis as unknown as { fetch: unknown }).fetch = async (input: unknown, init: RequestInit) => {
		const url = String(input);
		expect(url.endsWith('/api/auth/v1/logout')).toBe(true);
		expect(init.method).toBe('POST');
		return makeResponse({
			ok: false,
			status: 500,
			jsonData: {
				success: false,
				code: 500,
				message: 'Nope',
				data: null,
				errors: { e: 'x' }
			}
		});
	};

	try {
		const client = new ApiClient('https://example.test');
		client.set_access_token('a1');
		client.set_refresh_token('r1');

		const r = await client.logout();
		expect(r.success).toBe(false);
		expect(r.code).toBe(500);
		// Tokens should always be cleared on logout attempt, even on failure
		expect(client.get_access_token()).toBeNull();
		expect(client.get_refresh_token()).toBeNull();
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('logout clears stored tokens when the network request throws', async () => {
	const realFetch = globalThis.fetch;
	(globalThis as unknown as { fetch: unknown }).fetch = async () => {
		throw new Error('network unavailable');
	};

	try {
		const client = new ApiClient('https://example.test');
		client.set_access_token('a1');
		client.set_refresh_token('r1');

		const response = await client.logout();

		expect(response.success).toBe(false);
		expect(client.get_access_token()).toBeNull();
		expect(client.get_refresh_token()).toBeNull();
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('logout clears stored tokens when the response is not valid JSON', async () => {
	const realFetch = globalThis.fetch;
	(globalThis as unknown as { fetch: unknown }).fetch = async () => ({
		ok: true,
		status: 200,
		headers: new Headers(),
		async json() {
			throw new Error('bad json');
		}
	});

	try {
		const client = new ApiClient('https://example.test');
		client.set_access_token('a1');
		client.set_refresh_token('r1');

		const response = await client.logout();

		expect(response.success).toBe(false);
		expect(response.code).toBe(200);
		expect(client.get_access_token()).toBeNull();
		expect(client.get_refresh_token()).toBeNull();
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('invalid JSON response yields ApiResponse error with HTTP status code', async () => {
	const realFetch = globalThis.fetch;
	(globalThis as unknown as { fetch: unknown }).fetch = async () => {
		return {
			ok: true,
			status: 200,
			headers: new Headers(),
			async json() {
				throw new Error('bad json');
			}
		};
	};

	try {
		const client = new ApiClient('https://example.test', {
			enableTokens: false
		});
		const r = await client.get('/api/v1/test');
		expect(r.success).toBe(false);
		expect(r.code).toBe(200);
		expect(r.message).toMatch(/Failed to parse JSON response/);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('signs sorted query and POST parameters with the configured shared secret', async () => {
	const realFetch = globalThis.fetch;
	let capturedHeaders = new Headers();
	(globalThis as unknown as { fetch: unknown }).fetch = async (_input: unknown, init: RequestInit) => {
		capturedHeaders = new Headers(init.headers);
		return makeResponse();
	};

	try {
		const client = new ApiClient('https://example.test', {
			enableTokens: false,
			signer: new HmacSigner({ secret: 'shared-request-secret' })
		});
		await client.post('/api/items?z=9&a=3&a=1', { z: '2', a: '2' });

		const timestamp = capturedHeaders.get('x-apicore-timestamp');
		expect(timestamp).toMatch(/^\d+$/);
		const content = `POST\n/api/items\n${timestamp}\na=1&a=3&z=9\na=2&z=2`;
		const expected = createHmac('sha256', 'shared-request-secret').update(content).digest('hex');
		expect(capturedHeaders.get('x-apicore-signature')).toBe(expected);
		expect(client.getConfig().signer).toBeUndefined();
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('can put signing values in POST parameters', async () => {
	const realFetch = globalThis.fetch;
	let capturedBody = '';
	(globalThis as unknown as { fetch: unknown }).fetch = async (_input: unknown, init: RequestInit) => {
		capturedBody = String(init.body);
		return makeResponse();
	};

	try {
		const client = new ApiClient('https://example.test', {
			enableTokens: false,
			signer: new HmacSigner({ secret: 'shared', in: 'parameter', signature: 'sig', timestamp: 'ts' })
		});
		await client.post('/api/items', { a: '1' });

		const body = JSON.parse(capturedBody) as Record<string, string>;
		expect(body.a).toBe('1');
		expect(body.sig).toMatch(/^[a-f\d]{64}$/);
		expect(body.ts).toMatch(/^\d+$/);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test.each(['header', 'parameter'] as const)(
	'client and server signers interoperate with %s transport',
	async (transport) => {
		const options = { secret: 'shared', in: transport, signature: 'sig', timestamp: 'ts' } as const;
		const clientSigner = new HmacSigner(options);
		const serverSigner = new ServerHmacSigner(options);
		const headers = new Headers({ 'content-type': 'application/json' });
		const init = { method: 'POST', body: JSON.stringify({ z: '2', a: ['3', '1'] }) };
		const signed = await clientSigner.apply('https://example.test/items?b=2&a=0', init, headers);
		const url = new URL(String(signed.input));
		const body = typeof signed.body === 'string' ? (JSON.parse(signed.body) as Record<string, unknown>) : undefined;

		await expect(
			serverSigner.verify({
				method: 'POST',
				url: `${url.pathname}${url.search}`,
				headers: Object.fromEntries(headers.entries()),
				query: Object.fromEntries(url.searchParams.entries()),
				body
			})
		).resolves.toBeUndefined();
	}
);

test('reports unsupported signed multipart requests as a client error without fetching', async () => {
	const realFetch = globalThis.fetch;
	const fetchSpy = vi.fn();
	globalThis.fetch = fetchSpy;
	try {
		const client = new ApiClient('https://example.test', {
			signer: new HmacSigner({ secret: 'shared' })
		});
		const response = await client.post('/api/upload', { title: 'test' }, [
			['file', new Blob(['content'], { type: 'text/plain' })]
		]);

		expect(response.code).toBe(400);
		expect(response.message).toMatch(/Signed requests support/);
		expect(fetchSpy).not.toHaveBeenCalled();
	} finally {
		globalThis.fetch = realFetch;
	}
});
