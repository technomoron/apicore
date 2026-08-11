# Auth Modules 101

## What is an auth module?

An auth module is an optional plug-in that teaches `ApiServer` how to mint
access and refresh tokens for a signed-in user. It sits beside your storage
adapter and focuses on orchestration (what to issue, how to decorate metadata),
while storage keeps handling persistence like fetching users or storing
sessions.

## When do I need one?

- You want to bundle a full `/auth` feature area (e.g., login routes) in a
  separate package that wires itself into the server.
- You have multiple token strategies (password, API key, passkey) and prefer to
  keep their issuance logic in a shared module.
- You need to swap implementations depending on the environment and want a
  single injection point (e.g., mock tokens in tests, real tokens in
  production).

If your project already extends `ApiServer` and overrides methods like
`authenticateUser` or `storeToken` directly, you can ignore auth modules
entirely. They are there for teams that prefer composition over subclassing.

## The contract

```
interface AuthProviderModule<UserRow = unknown> {
	readonly moduleType: 'auth';
	readonly namespace: string;
	issueTokens(apiReq: ApiRequest, user: UserRow, metadata?: TokenMeta & { expires?: Date }): Promise<TokenPair>;
}
```

### `moduleType: 'auth'`

Signals to `ApiServer.api()` that this module is special. When you mount an auth
module, the server automatically registers it via `authModule()` so the instance
is available everywhere else.

### `namespace`

Pick the route prefix for any Fastify routes your module exposes (for example
`/auth`). `ApiServer` prepends its own `apiBasePath`, so if the base path is
`/api` and your namespace is `/auth`, everything mounts at `/api/auth`.

### `issueTokens(apiReq, user, metadata?)`

This is the only required method. The server calls it whenever it needs a fresh
access/refresh pair—for example inside a login handler. You receive:

- `apiReq`: the wrapper that includes the Fastify `req`/`res` objects plus the
  `server` instance, so you can call helpers like `jwtSign` or set cookies.
- `user`: the full user record (`UserRow`) that your storage adapter returned.
- `metadata`: optional token hints such as `scope`, `clientId`, or an explicit
  expiration date.

Return a `{ accessToken, refreshToken }` pair. Throw an `ApiError` (or any
error) to abort the flow if something goes wrong.

## Helpers you get for free

- `BaseAuthModule` already extends `ApiModule`, so you can mount subclasses
  directly via `server.api(...)`. Use the constructor to set a namespace and
  override `issueTokens` with your real implementation.
- `nullAuthModule` is the default placeholder and will throw if you try to issue
  tokens. Replace it during server setup with a concrete module.

## Built-in identity responses

The built-in `AuthModule` exposes `GET /api/auth/v1/me` for read-only
access-token identity lookup. It returns the effective request user as `user`.
When the current token is impersonating another user, the response also includes
`ruser` for the real user behind the session.

`GET /api/auth/v1/me/sessions` returns active session metadata for the
authenticated user with a non-secret `sessionId` handle. It never returns raw
access or refresh tokens. Use `DELETE /api/auth/v1/me/sessions/:sessionId` to
revoke a listed session; revocation is scoped to the authenticated user.

`POST /api/auth/v1/refresh` is token-only. It rotates and returns
`{ accessToken, refreshToken }`; clients that need identity should call `/me`,
letting the client refresh and retry transparently when an access token has
expired.

## Example skeleton

```ts
import { ApiModule, BaseAuthModule, ApiError } from '@technomoron/apicore-server';

export class MyAuthModule extends BaseAuthModule {
	public constructor() {
		super({ namespace: '/auth' });
	}

	public override async issueTokens(apiReq, user, metadata) {
		const { server, res } = apiReq;
		// Assume your storage returns a user object with an `id` field.
		const userId = user.id;

		const access = server.jwtSign({ uid: userId }, server.config.accessSecret, server.config.accessExpiry);
		const refresh = server.jwtSign({ uid: userId }, server.config.refreshSecret, server.config.refreshExpiry);

		if (!access.success || !refresh.success || !access.token || !refresh.token) {
			throw new ApiError({ code: 500, message: 'Unable to mint tokens' });
		}

		res.cookie(server.config.accessCookie, access.token, {
			httpOnly: true,
			domain: server.config.cookieDomain,
			maxAge: server.config.accessExpiry * 1000,
			sameSite: 'lax',
			secure: !server.config.devMode
		});

		return {
			accessToken: access.token,
			refreshToken: refresh.token
		};
	}
}

// Wire it up during server creation
server.api(new MyAuthModule());
```

## Tips

- If you need custom metadata, extend `TokenMeta` in your project and pass it
  through the `metadata` argument.
- Combine auth modules with a dedicated storage adapter so token issuance and
  persistence evolve together.
- For tests, create a lightweight module that returns deterministic token
  strings so you can assert behaviour without real signing keys.

## Security Note: CSRF

When using cookie-based auth, this package relies on cookie attributes (for
example SameSite/HttpOnly/Secure) but does not provide built-in CSRF token
issuance/validation. Treat CSRF protection as an application responsibility: add
anti-CSRF tokens (or equivalent middleware/policy) for state-changing browser
endpoints.
