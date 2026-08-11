# @technomoron/apicore-server

Fastify API framework with typed modules, JSON response envelopes, JWT and API-key authentication, OAuth, passkeys, multipart uploads, and resumable TUS uploads.

## Install

```bash
npm install @technomoron/apicore-server
```

The package provides ESM and CommonJS entry points. Sequelize-backed stores are optional and use the database driver selected by your application.

## Minimal server

```ts
import { ApiModule, ApiServer, type ApiRoute } from '@technomoron/apicore-server';

class StatusModule extends ApiModule<ApiServer> {
	public constructor() {
		super({ namespace: '/status' });
	}

	public override defineRoutes(): ApiRoute[] {
		return [
			{
				method: 'get',
				path: '/',
				auth: { type: 'none', req: 'any' },
				handler: async () => [200, { ready: true }]
			}
		];
	}
}

new ApiServer({
	apiHost: '127.0.0.1',
	apiPort: 3101,
	apiBasePath: '/api',
	origins: ['https://app.example.com']
})
	.api(new StatusModule())
	.start();
```

The route above is available at `/api/status`. Module handlers return `[status]`, `[status, data]`, or `[status, data, message]`. Successful and failed module requests use:

```json
{
	"success": true,
	"code": 200,
	"message": "Success",
	"data": {},
	"errors": {}
}
```

Throw `ApiError` for expected failures. Other exceptions become HTTP 500 responses without exposing internal error details unless development mode is enabled.

## Built-in areas

- [Base server and custom modules](docs/base/README.md)
- [Authentication and sessions](docs/auth/README.md)
- [Passkeys](docs/passkey/README.md)
- [OAuth](docs/oauth/README.md)
- [MIME and TUS uploads](docs/uploads/README.md)

Auth, passkey, OAuth, and TUS routes are mounted only when their module and required services are configured.

## Important configuration

| Option | Default | Purpose |
| --- | --- | --- |
| `apiBasePath` | `/api` | Prefix for core and `ApiModule` routes |
| `origins` | `[]` | Browser origins allowed by CORS; empty means same-origin only |
| `corsAllowAll` | `false` | Reflect any origin. Opt-in, and implied by `devMode` |
| `cookieSecure` | `'auto'` | `Secure` on auth cookies; `'auto'` needs `trustProxy` behind a proxy |
| `accessSecret` / `refreshSecret` | empty | JWT secrets required by `AuthModule` |
| `trustProxy` | `false` | Whether forwarded IP/protocol headers are trusted |
| `cookieHttpOnly` | `true` | Prevent browser JavaScript from reading auth cookies |
| `staticDirs` | unset | Map URL prefixes to directories served as static files |
| `signer` | unset | Default `RequestSigner` for routes mounted through `api()` |

## Signed requests and outbound HTTP

```ts
import { ApiServer, HmacSigner, rawRequest } from '@technomoron/apicore-server';

const signer = new HmacSigner({ secret: process.env.API_REQUEST_SECRET });
const server = new ApiServer({ signer });

await rawRequest('https://outside.example/items', {
	method: 'POST',
	body: { id: 42 },
	signer
});
```

The server signer is the default only for `api()` routes. Modules and routes can use another signer or `signer: false`. See [request-signing configuration](docs/configuration.md#signed-requests) for transport, canonicalization, replay, and browser limitations.
| `tokenStore` | unset | Application-provided token storage adapter |
| `apiKeyStore` | unset | Application-provided API-key storage adapter |
| `onStartError` | unset | Callback invoked when server startup fails |
| `swaggerEnabled` | `false` | Serve OpenAPI JSON at `<apiBasePath>/swagger` |
| `multipartEnabled` | `false` | Parse MIME multipart uploads |
| `uploadPath` | `./uploads` | Root containing the `mime` and `tus` directories |
| `uploadMax` | 30 MiB | Default MIME and TUS upload limit |

The served OpenAPI document is filtered to mounted built-in routes and rewrites core, auth, and TUS paths to their configured values.

## Storage

Memory stores are intended for local development and tests. Persistent Sequelize stores are available through package subpaths:

```ts
import { SqlAuthStore } from '@technomoron/apicore-server/auth-api/sql-auth-store';
import { SequelizeOAuthStore } from '@technomoron/apicore-server/oauth/sequelize';
import { SequelizePasskeyStore } from '@technomoron/apicore-server/passkey/sequelize';
import { SequelizeTokenStore } from '@technomoron/apicore-server/token/sequelize';
import { SequelizeUserStore } from '@technomoron/apicore-server/user/sequelize';
```

The application owns database migrations and synchronization.

`SequelizeTokenStore` stores complete access and refresh tokens in `TEXT` columns. When upgrading an existing database, change the `access` and `refresh` columns from `VARCHAR(768)` to `TEXT` and drop the old `jwt_access_unique` and `jwt_refresh_unique` indexes (or their prefixed equivalents).

## More documentation

Full documentation lives in [`docs/`](docs/README.md), which indexes the module API, every
configuration option, and each built-in module.

- [Documentation index and module API](docs/README.md)
- [Configuration reference](docs/configuration.md)
- [Architecture](docs/architecture.md)
- [OpenAPI document](docs/swagger/openapi.json)

## License

MIT
