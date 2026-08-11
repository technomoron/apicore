# Authentication module

`AuthModule` provides password login, refresh-token rotation, logout, current-user lookup, session management, and impersonation.

## Setup

```ts
import {
	ApiServer,
	AuthModule,
	MemAuthStore
} from '@technomoron/apicore-server';

const store = new MemAuthStore();
await store.initialise();

const server = new ApiServer({
	accessSecret: process.env.ACCESS_SECRET,
	refreshSecret: process.env.REFRESH_SECRET,
	accessExpiry: 15 * 60,
	refreshExpiry: 30 * 24 * 60 * 60,
	sessionRefreshExpiry: 24 * 60 * 60
})
	.authStorage(store)
	.api(new AuthModule());

server.start();
```

`MemAuthStore` is for development and tests. Use `SqlAuthStore` or an application adapter for persistent users and sessions.

## Core routes

| Method and path | Authentication | Purpose |
| --- | --- | --- |
| `POST /v1/login` | None | Verify credentials and issue tokens |
| `POST /v1/refresh` | None, refresh credential required | Rotate a refresh token |
| `POST /v1/logout` | Optional | Revoke the current refresh token |
| `GET /v1/me` | Required | Return effective user and optional real impersonating user |
| `GET /v1/me/sessions` | Required | List safe session metadata |
| `DELETE /v1/me/sessions/:sessionId` | Required | Revoke one owned session |
| `POST /v1/impersonations` | Strict | Start an allowed impersonation |
| `DELETE /v1/impersonations` | Strict | End impersonation and return to the real user |

With the default namespace and core base path, these routes start with `/api/auth`.

## Token lifetime

`accessExpiry` and `refreshExpiry` are seconds. When `keepSession` is false, the refresh JWT, stored record, and cookie use `sessionRefreshExpiry`. A positive numeric `keepSession` value selects that custom refresh lifetime. Session cookies omit `Max-Age`, but their signed refresh token still expires.

## Cookies and browser security

Auth cookies default to `cookieHttpOnly: true`, `cookieSecure: 'auto'`, `cookieSameSite: 'lax'`, and `cookiePath: '/'`; `cookieDomain` is unset.

`cookieSecure: 'auto'` reads `x-forwarded-proto` only when `trustProxy` is enabled, so behind a TLS-terminating proxy with the default `trustProxy: false` auth cookies are issued **without** `Secure`. Set `trustProxy` to your proxy depth (or `cookieSecure: true`). ApiCore warns at startup when it sees this combination. See [Cookies behind a proxy](../configuration.md#cookies-behind-a-proxy) for the full matrix.

Setting `cookieSameSite: 'none'` — required for cross-site browser clients — removes the protection that keeps a permissive CORS configuration contained, so pair it with an explicit `origins` allowlist rather than `corsAllowAll`.

Cookie authentication does not provide CSRF tokens; applications must add CSRF protection for state-changing browser requests.

## Storage contract

An auth adapter owns user lookup, password verification, public-user filtering, and token persistence. `AuthModule` owns route orchestration and token issuance. The server can also use separate `TokenStore` and `ApiKeyStore` implementations.

See [Writing an auth module](writing-an-auth-module.md) for custom auth-provider modules and adapter details.
