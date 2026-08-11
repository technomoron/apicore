# Base server module

The base area contains `ApiServer`, `ApiModule`, request handling, validation, authentication hooks, OpenAPI serving, the ping endpoint, and upload cleanup administration.

## Routes

These core routes are always mounted under `apiBasePath`:

| Method and path | Authentication | Purpose |
| --- | --- | --- |
| `GET /v1/ping` | None | Version, uptime, and server start metadata |
| `POST /v1/uploads/purge` | Strict, admin class | Remove expired MIME files and incomplete TUS uploads |

Swagger is optional and defaults to `<apiBasePath>/swagger` when `swaggerEnabled` is true.

## Custom modules

```ts
import { ApiModule, type ApiRoute } from '@technomoron/apicore-server';

class ProjectsModule extends ApiModule {
	public static override defaultNamespace = '/projects';

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

Object schemas for bodies, query strings, and path parameters default to `additionalProperties: false`. Set `strictProps: false` on the route or specify `additionalProperties` in the schema to change that behavior.

## Authentication modes

| Type | Behavior |
| --- | --- |
| `none` | No authentication |
| `maybe` | Anonymous or authenticated |
| `yes` | Valid access JWT, cookie, or enabled API key |
| `strict` | Authenticated and backed by a current stored token |
| `apikey` | API key only |

`req` selects the authorization class. The base server allows `any` and requires `tokenData.role === 'admin'` for `admin`. Applications can override `authorize()` to use their own roles and permissions.

Set the server `signer` to require signed requests by default on routes mounted through `api()`. `HmacSigner` provides shared-secret HMAC-SHA256 signing. Modules and routes can override the default signer or set `signer: false` for an unsigned exception. Signatures use headers by default and can instead use query or body parameters. Query and top-level body parameters are kept separate and sorted by name and content before signing.

For outbound calls, `rawRequest()` wraps native `fetch` with arbitrary headers, JSON body serialization, and an optional signer:

```ts
await rawRequest('https://outside.example/items', {
	method: 'POST',
	headers: { Accept: 'application/json' },
	body: { id: 42 },
	signer: new HmacSigner({ secret: process.env.OUTBOUND_SECRET })
});
```

## Storage and operational options

`tokenStore` and `apiKeyStore` accept application-provided storage adapters. The bundled memory stores are for temporary use. `JsonApiKeyStore` stores API-key secrets as plain text, so protect the file with restrictive permissions. The built-in API-key records do not expire and do not contain permissions; rotate or revoke keys in your application, and enforce permissions in `authorize()`. Setting `euid` grants the key full impersonation of that effective user.

`staticDirs` maps URL prefixes to directories served by Fastify. `cookieHttpOnly` defaults to `true`; turn it off only when browser JavaScript must read auth cookies. `onStartError` receives a startup error after logging and before `start()` returns.

## OpenAPI

The shipped document is a reference for built-in operations. At runtime it is filtered to mounted built-in routes and rewritten for configured core, auth, and TUS paths. Optional passkey and OAuth operations disappear when their services are not mounted.
