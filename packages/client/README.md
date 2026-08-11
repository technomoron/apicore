# @technomoron/apicore-client

Typed HTTP client for APIs built with `@technomoron/apicore-server`.

## Install

```bash
npm install @technomoron/apicore-client
```

Both ESM and CommonJS are supported:

```ts
import { ApiClient } from '@technomoron/apicore-client';
```

```js
const { ApiClient } = require('@technomoron/apicore-client');
```

## Create a client

```ts
const client = new ApiClient('https://api.example.com', {
	apiBasePath: '/api',
	authBasePath: '/api/auth/v1',
	timeout: 15_000,
	maxRetries: 1
});

const ping = await client.ping();
if (!ping.success) {
	console.error(ping.code, ping.message, ping.errors);
}
```

`apiBasePath` controls core helpers such as `ping()`. `authBasePath` controls login, refresh, logout, identity, and session helpers. Set both when the server uses custom paths.

## Requests

```ts
const result = await client.get<{ projects: string[] }>('/api/v1/projects');
const created = await client.post<{ id: string }>('/api/v1/projects', {
	name: 'Example'
});
```

Every method returns `ApiResponse<T>` rather than throwing for normal HTTP, network, timeout, or JSON parsing errors:

```ts
if (created.success) {
	console.log(created.data.id);
} else {
	console.error(created.code, created.message, created.errors);
}
```

## Authentication

```ts
const login = await client.login('user@example.com', 'secret');
const me = await client.me();
const sessions = await client.sessions();

if (sessions.success && sessions.data.sessions.length > 0) {
	await client.revokeSession(sessions.data.sessions[0].sessionId);
}

await client.logout();
```

Access and refresh tokens are held in memory by default. Override the token getter and setter methods in a subclass when tokens must be stored elsewhere. Logout always clears local credentials, including when the server is unavailable or returns an invalid response.

When a request receives HTTP 401 and a refresh token is available, the client performs at most one refresh and retries the original request. This authentication retry is separate from `maxRetries`, which applies to timeouts.

## API keys

```ts
const automation = new ApiClient('https://api.example.com', {
	apiKey: process.env.API_KEY,
	enableTokens: false
});
```

The raw key is never returned by `getConfig()`.

## Signed requests

```ts
import { ApiClient, HmacSigner } from '@technomoron/apicore-client';

const client = new ApiClient('https://api.example.com', {
	signer: new HmacSigner({ secret: process.env.API_REQUEST_SECRET })
});
```

The signature defaults to `X-ApiCore-Signature` with a Unix timestamp in `X-ApiCore-Timestamp`. Set `in: 'parameter'` to put both values in the query string for GET and DELETE, or in the JSON/form body for other methods. `signature` and `timestamp` customize their names.

Query-string and top-level JSON or URL-encoded body parameters are sorted separately by name and content before signing. Signed requests support string and `URLSearchParams` bodies; multipart bodies return a client-side 400 response without making a request.

## Multipart requests

Pass `File` or `Blob` values as the third argument to `post()`:

```ts
await client.post('/api/v1/images', { title: 'Cover' }, [
	['image', imageFile]
]);
```

TUS is a separate resumable-upload protocol. Use a TUS client against the server’s configured TUS endpoint.

## License

MIT
