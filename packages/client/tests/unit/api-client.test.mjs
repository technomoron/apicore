import assert from 'node:assert/strict';
import test from 'node:test';

import { ApiClient } from '../../dist/esm/index.js';

function makeResponse({ ok, status, jsonData, headers } = {}) {
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

function headersToObject(headers) {
	const obj = {};
	for (const [k, v] of headers.entries()) obj[k.toLowerCase()] = v;
	return obj;
}

test('ApiClient strips trailing slash from apiUrl and builds url correctly', async () => {
	const realFetch = globalThis.fetch;
	const calls = [];
	globalThis.fetch = async (input, init) => {
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
		assert.equal(r.success, true);
		assert.equal(String(calls[0].input), 'https://example.test/api/v1/ping');
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
	assert.deepEqual(client.getConfig(), {
		apiKey: '***',
		timeout: 1,
		maxRetries: 2,
		debug: true,
		enableTokens: true,
		authBasePath: '/api/auth/v1'
	});

	client.configure({
		apiKey: null,
		timeout: 10,
		maxRetries: 0,
		debug: false,
		enableTokens: false
	});
	assert.deepEqual(client.getConfig(), {
		apiKey: null,
		timeout: 10,
		maxRetries: 0,
		debug: false,
		enableTokens: false,
		authBasePath: '/api/auth/v1'
	});
});

test('login stores tokens and subsequent requests use access token when tokens enabled', async () => {
	const realFetch = globalThis.fetch;
	const calls = [];
	globalThis.fetch = async (input, init) => {
		const url = String(input);
		const hdrs = headersToObject(init.headers);
		calls.push({ url, init, hdrs });

		if (url.endsWith('/api/auth/v1/login')) {
			assert.equal(init.method, 'POST');
			assert.equal(init.credentials, 'include');
			assert.equal(hdrs['content-type'], 'application/json');
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

		assert.equal(hdrs['authorization'], 'Bearer a1');
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
		assert.equal(login.success, true);

		const r = await client.get('/api/v1/ping');
		assert.equal(r.success, true);
		assert.equal(calls.length, 2);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('login failure returns an error ApiResponse with status and errors', async () => {
	const realFetch = globalThis.fetch;
	globalThis.fetch = async (input) => {
		const url = String(input);
		assert.ok(url.endsWith('/api/auth/v1/login'));
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
		assert.equal(r.success, false);
		assert.equal(r.code, 401);
		assert.equal(r.message, 'bad creds');
		assert.deepEqual(r.errors, { login: 'nope' });
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('apiKey wins over access token for Authorization header', async () => {
	const realFetch = globalThis.fetch;
	globalThis.fetch = async (_input, init) => {
		const hdrs = headersToObject(init.headers);
		assert.equal(hdrs['authorization'], 'Bearer api-key-1');
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
		assert.equal(r.success, true);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('tokens disabled: access token is not attached', async () => {
	const realFetch = globalThis.fetch;
	globalThis.fetch = async (_input, init) => {
		const hdrs = headersToObject(init.headers);
		assert.ok(!('authorization' in hdrs));
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
		assert.equal(r.success, true);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('401 with no refresh token does not attempt refresh', async () => {
	const realFetch = globalThis.fetch;
	let callCount = 0;

	globalThis.fetch = async () => {
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
		assert.equal(r.success, false);
		assert.equal(r.code, 401);
		assert.equal(callCount, 1);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('request with files uses FormData and does not force Content-Type header', async () => {
	const realFetch = globalThis.fetch;
	globalThis.fetch = async (input, init) => {
		const hdrs = headersToObject(init.headers);
		assert.ok(!('content-type' in hdrs));
		assert.equal(init.method, 'POST');
		assert.equal(init.credentials, 'include');

		assert.ok(init.body instanceof FormData);
		const entries = Array.from(init.body.entries());

		// payload fields
		assert.ok(entries.some(([k, v]) => k === 'a' && v === '1'));
		assert.ok(entries.some(([k, v]) => k === 'obj' && v === '{"x":2}'));

		// file fields
		assert.ok(entries.some(([k, v]) => k === 'f1' && typeof v === 'object'));
		assert.ok(entries.some(([k, v]) => k === 'files' && typeof v === 'object'));

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
		assert.equal(r.success, true);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('401 triggers refresh once when refresh token exists, then retries original request with new access token', async () => {
	const realFetch = globalThis.fetch;
	let testCallCount = 0;
	let refreshCallCount = 0;

	globalThis.fetch = async (input, init) => {
		const url = String(input);
		const hdrs = headersToObject(init.headers);

		if (url.endsWith('/api/auth/v1/refresh')) {
			refreshCallCount++;
			assert.equal(hdrs['content-type'], 'application/json');
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
				assert.equal(hdrs['authorization'], 'Bearer old-access');
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

			assert.equal(hdrs['authorization'], 'Bearer new-access');
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
		assert.equal(r.success, true);
		assert.equal(testCallCount, 2);
		assert.equal(refreshCallCount, 1);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('refresh failure returns an error and does not retry refresh', async () => {
	const realFetch = globalThis.fetch;
	let testCallCount = 0;
	let refreshCallCount = 0;

	globalThis.fetch = async (input) => {
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
		assert.equal(r.success, false);
		assert.equal(r.code, 401);
		assert.equal(r.message, 'refresh bad');
		assert.equal(testCallCount, 1);
		assert.equal(refreshCallCount, 1);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('401 after refresh does not attempt a second refresh', async () => {
	const realFetch = globalThis.fetch;
	let refreshCallCount = 0;

	globalThis.fetch = async (input) => {
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
		assert.equal(r.success, false);
		assert.equal(r.code, 401);
		assert.equal(refreshCallCount, 1);
	} finally {
		globalThis.fetch = realFetch;
	}
});
test('timeout (AbortError) retries up to maxRetries', async () => {
	const realFetch = globalThis.fetch;
	let callCount = 0;

	globalThis.fetch = async () => {
		callCount++;
		if (callCount === 1) {
			// safeFetch treats { name: 'AbortError' } as a timeout and throws ApiResponse(code=504)
			throw { name: 'AbortError' };
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
		assert.equal(r.success, true);
		assert.equal(callCount, 2);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('circular JSON body returns ApiResponse error with code 400', async () => {
	const realFetch = globalThis.fetch;
	globalThis.fetch = async () => {
		throw new Error('fetch should not be called when body serialization fails');
	};

	try {
		const client = new ApiClient('https://example.test', {
			enableTokens: false
		});
		const body = {};
		body.self = body;
		const r = await client.post('/api/v1/test', body);
		assert.equal(r.success, false);
		assert.equal(r.code, 400);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('network error codes are mapped to user-friendly messages and HTTP-ish codes (Node branch)', async () => {
	const realFetch = globalThis.fetch;
	globalThis.fetch = async () => {
		throw {
			code: 'ECONNREFUSED',
			message: 'connect ECONNREFUSED 127.0.0.1'
		};
	};

	try {
		const client = new ApiClient('https://example.test', {
			enableTokens: false,
			maxRetries: 0
		});
		const r = await client.get('/api/v1/test');
		assert.equal(r.success, false);
		assert.equal(r.code, 503);
		assert.match(r.message, /Fetch failed: Connection refused by server/);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('browser fetch failure message (browser branch)', async () => {
	const realFetch = globalThis.fetch;
	const realWindow = globalThis.window;

	// Force the browser branch in safeFetch
	globalThis.window = { document: {} };
	globalThis.fetch = async () => {
		throw new TypeError('Failed to fetch');
	};

	try {
		const client = new ApiClient('https://example.test', {
			enableTokens: false,
			maxRetries: 0
		});
		const r = await client.get('/api/v1/test');
		assert.equal(r.success, false);
		assert.equal(r.code, 503);
		assert.match(r.message, /Possible CORS issue or server unreachable/);
	} finally {
		globalThis.fetch = realFetch;
		globalThis.window = realWindow;
	}
});

test('HTTP ok but payload.success=false returns an error response', async () => {
	const realFetch = globalThis.fetch;
	globalThis.fetch = async () => {
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
		assert.equal(r.success, false);
		assert.equal(r.code, 400);
		assert.equal(r.message, 'Nope');
		assert.deepEqual(r.errors, { a: 'b' });
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('apiKey auth failures do not attempt token refresh', async () => {
	const realFetch = globalThis.fetch;
	const calls = [];

	globalThis.fetch = async (input, init) => {
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
		assert.equal(r.success, false);
		assert.equal(r.code, 401);
		assert.equal(calls.length, 1);
		assert.ok(!calls.some((c) => c.url.endsWith('/api/auth/v1/refresh')));
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('logout success clears stored tokens', async () => {
	const realFetch = globalThis.fetch;
	let didLogout = false;

	globalThis.fetch = async (input, init) => {
		const url = String(input);

		if (url.endsWith('/api/auth/v1/logout')) {
			didLogout = true;
			assert.equal(init.method, 'POST');
			assert.equal(init.credentials, 'include');
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

		// After logout, the client should not attach Authorization from tokens
		const hdrs = headersToObject(init.headers);
		assert.ok(!('authorization' in hdrs));
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
		assert.equal(r.success, true);
		assert.equal(didLogout, true);
		assert.equal(client.get_access_token(), null);
		assert.equal(client.get_refresh_token(), null);

		const after = await client.get('/api/v1/test');
		assert.equal(after.success, true);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('logout failure does not clear stored tokens', async () => {
	const realFetch = globalThis.fetch;
	globalThis.fetch = async (input, init) => {
		const url = String(input);
		assert.ok(url.endsWith('/api/auth/v1/logout'));
		assert.equal(init.method, 'POST');
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
		assert.equal(r.success, false);
		assert.equal(r.code, 500);
		assert.equal(client.get_access_token(), null);
		assert.equal(client.get_refresh_token(), null);
	} finally {
		globalThis.fetch = realFetch;
	}
});

test('invalid JSON response yields ApiResponse error with HTTP status code', async () => {
	const realFetch = globalThis.fetch;
	globalThis.fetch = async () => {
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
		assert.equal(r.success, false);
		assert.equal(r.code, 200);
		assert.match(r.message, /Failed to parse JSON response/);
	} finally {
		globalThis.fetch = realFetch;
	}
});
