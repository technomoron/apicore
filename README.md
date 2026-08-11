# apicore

[![CI](https://github.com/technomoron/apicore/actions/workflows/ci.yml/badge.svg)](https://github.com/technomoron/apicore/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@technomoron/apicore-server)](https://www.npmjs.com/package/@technomoron/apicore-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Fastify API server framework in strict TypeScript, with batteries included.

## Packages

| Package                                           | Description                                                                 |
| ------------------------------------------------- | --------------------------------------------------------------------------- |
| [`@technomoron/apicore-server`](packages/server/) | Server framework — Fastify wrapper with auth, JWT, OAuth, passkeys, uploads |
| [`@technomoron/apicore-client`](packages/client/) | HTTP client — typed client for apicore-server APIs                          |

## Install

```bash
# server
pnpm add @technomoron/apicore-server

# client
pnpm add @technomoron/apicore-client
```

## Quick Start

```ts
import { ApiError, ApiModule, ApiServer, BaseAuthAdapter } from '@technomoron/apicore-server';

type DemoUser = { id: string; email: string; password: string };

class DemoStorage extends BaseAuthAdapter<DemoUser, Omit<DemoUser, 'password'>> {
	private readonly users = new Map<string, DemoUser>([
		['1', { id: '1', email: 'demo@example.com', password: 'secret' }]
	]);

	public override async getUser(uid: unknown) {
		return this.users.get(String(uid)) ?? null;
	}

	public override getUserPasswordHash(user: DemoUser) {
		return user.password;
	}

	public override filterUser(user: DemoUser) {
		const { password: _password, ...safe } = user;
		void _password;
		return safe;
	}
}

class UserModule extends ApiModule<ApiServer> {
	public constructor() {
		super({ namespace: '/users' });
	}

	public override defineRoutes() {
		return [
			{
				method: 'get' as const,
				path: '/',
				auth: { type: 'yes' as const, req: 'any' as const },
				handler: async ({ server, tokenData }) => {
					const storage = server.getAuthStorage();
					const user = tokenData ? await storage.getUser(tokenData.uid) : null;
					if (!user) {
						throw new ApiError({ code: 404, message: 'User not found' });
					}
					return [200, storage.filterUser(user)];
				}
			}
		];
	}
}

new ApiServer({
	apiPort: 3101,
	apiHost: '127.0.0.1',
	accessSecret: 'replace-me',
	refreshSecret: 'replace-me-too'
})
	.authStorage(new DemoStorage())
	.api(new UserModule())
	.finalize()
	.start();
```

## Route Handler Contract

Handlers return `[status]`, `[status, data]`, or `[status, data, message]`.
Throw `ApiError` for controlled failures.
Route definitions may also include a Fastify `schema` object. ApiCore applies its documented object-property defaults, then passes the schema to Fastify/Ajv for request validation.
For `body`, `querystring`, and `params` object schemas, `additionalProperties` defaults to `false` unless the route sets `strictProps: false` or the schema sets `additionalProperties` explicitly.
For non-Ajv validators, register a server adapter with `server.addValidatorAdapter(...)` and attach an adapter-specific `validator` contract to the route. Adapters should either throw `ApiError` directly or normalize foreign validation failures into `ApiErrorParams`.

Example adapter using Zod in your application:

```ts
import { z, ZodError, type ZodTypeAny } from 'zod';
import { ApiModule, ApiServer, type ApiRoute, type ApiRouteValidatorAdapter } from '@technomoron/apicore-server';

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
			const path = issue.path.join('.') || 'body';
			errors[path] = issue.message;
		}
		return { code: 400, message: 'Validation failed', errors };
	}
};

class UserModule extends ApiModule {
	public static override defaultNamespace = '/users';

	public override defineRoutes(): ApiRoute[] {
		return [
			{
				method: 'post',
				path: '/',
				auth: { type: 'none', req: 'any' },
				validator: z.object({ name: z.string().min(1) }),
				handler: async ({ req }) => [201, req.body]
			}
		];
	}
}

new ApiServer({
	/* ... */
})
	.addValidatorAdapter(zodAdapter)
	.api(new UserModule());
```

The adapter decides what the `validator` contract means, so you can validate `body`, `query`, `params`, or any other request shape that fits your app.

## Core Server Config

| Option                           | Default | Description               |
| -------------------------------- | ------- | ------------------------- |
| `apiBasePath`                    | `/api`  | URL prefix for all routes |
| `apiPort` / `apiHost`            | —       | Listen address            |
| `accessSecret` / `refreshSecret` | —       | JWT signing secrets       |
| `accessExpiry` / `refreshExpiry` | —       | Token lifetimes           |
| `origins`                        | `[]`    | Cross-origin allowlist. Empty means same-origin only |
| `corsAllowAll`                   | `false` | Reflect any origin. Opt-in; implied by `devMode`     |
| `trustProxy`                     | `false` | Proxy header trust depth. Set this behind a proxy    |
| `cookieSecure`                   | `auto`  | `Secure` on auth cookies; `auto` needs `trustProxy`  |
| `cookieSameSite`                 | `lax`   | `SameSite` on auth cookies                           |
| `debug`                          | `false` | Verbose request logging   |

See the [configuration reference](packages/server/docs/configuration.md) for all options.

## Optional Modules

| Module                         | Import                                               |
| ------------------------------ | ---------------------------------------------------- |
| Auth (login/logout/refresh/me) | `AuthModule` from `@technomoron/apicore-server`      |
| OAuth                          | `@technomoron/apicore-server/oauth/sequelize`        |
| Passkeys / WebAuthn            | `@technomoron/apicore-server/passkey/sequelize`      |
| File uploads (Tus)             | `TusUploadModule` from `@technomoron/apicore-server` |

Passkey registration is a self-service flow: `/api/auth/v1/passkeys/challenge` and `/api/auth/v1/passkeys/verify` require the authenticated, non-impersonating actor to match the target user when `action: 'register'`. The authenticate flow remains public.

Auth identity responses from `/api/auth/v1/me` expose the effective request user as `user`. When a token is impersonating another user, the response also includes `ruser` for the real user behind the session. Refresh responses only return replacement tokens.

## Accessing Fastify Directly

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

## Docs

Everything lives under [`packages/server/docs/`](packages/server/docs/README.md).

- [Documentation index and module API](packages/server/docs/README.md)
- [Configuration reference](packages/server/docs/configuration.md)
- [Architecture](packages/server/docs/architecture.md)
- [Base Server Module](packages/server/docs/base/README.md)
- [Authentication Module](packages/server/docs/auth/README.md)
- [Writing an auth module](packages/server/docs/auth/writing-an-auth-module.md)
- [Passkey Module](packages/server/docs/passkey/README.md)
- [OAuth Module](packages/server/docs/oauth/README.md)
- [Upload Module](packages/server/docs/uploads/README.md)
- [OpenAPI spec](packages/server/docs/swagger/openapi.json)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — © 2025 Bjørn Erik Jacobsen / Technomoron
