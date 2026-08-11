# apicore-server documentation

Start here. This page documents the module API that every built-in and custom module shares; the
per-module pages cover their own routes and storage contracts.

| Page | Contents |
| --- | --- |
| [Configuration](configuration.md) | Every `ApiServerConf` option, cookie and proxy behaviour, startup warnings |
| [Architecture](architecture.md) | Package structure, design decisions, store backends |
| [Base server](base/README.md) | Core routes, custom modules, authentication modes |
| [Authentication](auth/README.md) | Login, sessions, impersonation, cookie security |
| [Writing an auth module](auth/writing-an-auth-module.md) | Building your own auth provider |
| [Passkeys](passkey/README.md) | WebAuthn registration and authentication |
| [OAuth](oauth/README.md) | Authorization code flow, PKCE, clients |
| [Uploads](uploads/README.md) | MIME multipart, resumable TUS, cleanup |
| [OpenAPI](swagger/openapi.json) | Generated specification |

## Module API

Every feature area is an `ApiModule` mounted with `server.api(...)`. Modules are mounted at
`apiBasePath + namespace`, and built-in modules only register their routes when their required
services are configured.

| Module | Namespace | Mounted when |
| --- | --- | --- |
| Core (ping, upload purge) | `/v1` | Always |
| `AuthModule` | `/auth` | Mounted explicitly, with a user store and token store |
| Passkey routes | `/auth/v1/passkeys` | A passkey service is configured on the auth storage |
| OAuth routes | `/auth/v1/oauth2` | An OAuth store is configured on the auth storage |
| `TusUploadModule` | configurable, default `/api/v1/upload` | Mounted explicitly with an explicit `auth` option |

### Defining a module

```ts
import { ApiModule, type ApiRoute } from '@technomoron/apicore-server';

class ProjectsModule extends ApiModule {
	public static override defaultNamespace = '/projects';

	public override checkConfig(): boolean {
		return true; // return false, or throw, to prevent mounting
	}

	public override defineRoutes(): ApiRoute[] {
		return [
			{
				method: 'get',
				path: '/',
				auth: { type: 'yes', req: 'any' },
				schema: {
					querystring: {
						type: 'object',
						properties: { limit: { type: 'integer', minimum: 1 } }
					}
				},
				handler: async ({ req }) => [200, { limit: req.query.limit ?? 20 }]
			}
		];
	}
}
```

Set the namespace through the constructor or a `defaultNamespace` static field. `onMount()` runs after
the module is attached, for modules that need direct server integration.

### Route contract

| Field | Purpose |
| --- | --- |
| `method` | `get`, `post`, `put`, `patch`, or `delete` |
| `path` | Appended to the module namespace |
| `auth` | `{ type, req }` — see [authentication modes](base/README.md#authentication-modes) |
| `handler` | Receives `ApiRequest`, resolves a tuple |
| `schema` | Optional Fastify/Ajv schema |
| `validator` | Optional adapter-resolved contract for non-Ajv validation |
| `strictProps` | Set `false` to allow additional properties (default `true`) |
| `signer` | Override the module/server request signer, or set `false` for an unsigned route |

Handlers resolve `[status]`, `[status, data]`, or `[status, data, message]`. Every response — success or
failure — uses the same envelope:

```json
{ "success": true, "code": 200, "message": "Success", "data": {}, "errors": {} }
```

Throw `ApiError({ code, message, data?, errors? })` for expected failures. Unhandled exceptions flatten
through `guessExceptionText` and return a 500 envelope without leaking internals unless `debug` is on.

### Request object

Each handler receives an `ApiRequest`:

| Member | Purpose |
| --- | --- |
| `req` / `res` | Underlying request and response adapter, for streaming or downloads |
| `server` | The `ApiServer` instance |
| `tokenData` | Decoded JWT claims, or `null` |
| `authToken` | Stored token row, when strict validation resolved one |
| `apiKey` | Resolved API key, when the request authenticated with one |
| `authMethod` | `'bearer'`, `'cookie'`, `'param'`, `'apikey'`, or `null` |
| `getClientIp()` / `getClientIpChain()` | Client address, resolved through `trustProxy` |
| `getRealUid()` / `isImpersonating()` | Real actor behind an impersonating session |

### Schema validation

Route `schema` objects pass through to Fastify and are validated by Ajv; failures normalize into the
standard error envelope. For `body`, `querystring`, and `params` object schemas, ApiCore defaults
`additionalProperties` to `false` when the schema omits it. Set `strictProps: false` on the route, or
set `additionalProperties` explicitly, to override. The default applies to top-level schemas only —
nested objects keep Ajv's own behaviour.

### Non-Ajv validators

Register an adapter and attach a `validator` contract to the route. The adapter decides what the
contract means, so it can validate `body`, `query`, `params`, or a combined shape.

```ts
import { z, ZodError, type ZodTypeAny } from 'zod';
import type { ApiRouteValidatorAdapter } from '@technomoron/apicore-server';

const zodAdapter: ApiRouteValidatorAdapter = {
	name: 'zod',
	supports: (contract) => Boolean(contract && typeof contract === 'object' && 'safeParse' in contract),
	validate: ({ contract, apiReq }) => {
		const result = (contract as ZodTypeAny).safeParse(apiReq.req.body);
		if (!result.success) {
			throw result.error;
		}
	},
	normalizeError: (error) => {
		if (!(error instanceof ZodError)) {
			return null;
		}
		const errors: Record<string, string> = {};
		for (const issue of error.issues) {
			errors[issue.path.join('.') || 'body'] = issue.message;
		}
		return { code: 400, message: 'Validation failed', errors };
	}
};

new ApiServer({
	/* ... */
})
	.addValidatorAdapter(zodAdapter)
	.api(new UserModule());
```

Adapters must be registered before `finalize()`. Duplicate names, and contracts matching more than one
adapter, are rejected at mount time.

## Raw Fastify access

`ApiModule` routes always respond through the tuple wrapper. For raw control — streaming, webhooks,
custom protocols — use the Fastify instance directly:

```ts
const server = new ApiServer({
	/* ... */
})
	.authStorage(storage)
	.api(new UserModule())
	.finalize();

server.fastify.get('/health', async () => ({ status: 'ok' }));
server.start();
```

Compatibility routes registered with `useExpress()` receive the original Node request stream plus
`req.fastifyRequest`, so upload endpoints can use the Fastify multipart plugin without registering it
again:

```ts
server.useExpress('/creative-upload', async (req, res) => {
	const file = await req.fastifyRequest.file();
	const buffer = file ? await file.toBuffer() : null;
	res.status(200).json({ filename: file?.filename ?? null, size: buffer?.length ?? 0 });
});
```

ApiCore only auto-parses multipart bodies for `ApiModule` routes; compatibility routes keep the stream
available.

## Token helpers

| Helper | Returns |
| --- | --- |
| `jwtSign(payload, secret, expiresInSeconds, options?)` | `{ success, token?, error? }` |
| `jwtVerify(token, secret, options?)` | `{ success, data?, expired?, error? }` |
| `jwtDecode(token)` | `{ success, data? }` — no signature validation |

Verification is restricted to HMAC algorithms (`HS256`, `HS384`, `HS512`) by default.

Store issued tokens with `storeToken` so they can be revoked; use `getToken`, `deleteToken`,
`listTokens`, and `updateToken` to manage sessions. See [authentication](auth/README.md) for the
session routes.

## Setup order

Call configuration methods before `finalize()` — `authStorage()`, `authModule()`, `setTokenStore()`,
`setApiKeyStore()`, `addValidatorAdapter()`, `api()`, and `useExpress()` all throw once the server is
finalized. Always `finalize()` before `start()`.
