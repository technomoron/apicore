# Configuration reference

Every option is passed to the `ApiServer` constructor as a partial object; anything omitted takes the
default below.

```ts
const server = new ApiServer({
	apiPort: 3101,
	apiHost: '127.0.0.1',
	origins: ['https://app.example.com'],
	accessSecret: process.env.ACCESS_SECRET,
	refreshSecret: process.env.REFRESH_SECRET,
	trustProxy: 1
});
```

If you extend `ApiServerConf` downstream, update `fillConfig` too so defaults stay consistent.

## HTTP and routing

| Option | Default | Description |
| --- | --- | --- |
| `apiPort` | `3101` | Fastify listen port |
| `apiHost` | `localhost` | Bind address |
| `apiBasePath` | `/api` | Prefix applied before every module namespace |
| `staticDirs` | unset | Map of URL prefixes to directories served as static files |
| `swaggerEnabled` | `false` | Serve the OpenAPI JSON document |
| `swaggerPath` | `<apiBasePath>/swagger` | Path for the OpenAPI JSON endpoint |
| `onStartError` | unset | Callback invoked when server startup fails |

## Cross-origin requests

| Option | Default | Description |
| --- | --- | --- |
| `origins` | `[]` | Cross-origin allowlist. Empty means **same-origin only** |
| `corsAllowAll` | `false` | Reflect *any* origin. Implied by `devMode` when `origins` is empty |

An empty `origins` list emits no `Access-Control-Allow-Origin`, so browsers refuse to expose responses
to other sites. Requests without an `Origin` header (curl, server-to-server) are unaffected, and
same-origin `POST`/`PUT`/`DELETE` — which *do* carry an `Origin` header — keep working. Listing origins
reflects those and rejects others with 403.

`corsAllowAll` turns off cross-origin protection for every site on the internet. It is ignored whenever
`origins` is non-empty, and warns at startup outside `devMode`.

## Authentication cookies

| Option | Default | Description |
| --- | --- | --- |
| `accessCookie` | `dat` | Access token cookie name |
| `refreshCookie` | `drt` | Refresh token cookie name |
| `cookieDomain` | `''` | Domain applied to auth cookies |
| `cookiePath` | `/` | Path applied to auth cookies |
| `cookieHttpOnly` | `true` | Prevent browser JavaScript from reading auth cookies |
| `cookieSecure` | `'auto'` | Mark cookies `Secure`: `true`, `false`, or `'auto'` |
| `cookieSameSite` | `'lax'` | `SameSite` attribute: `'lax'`, `'strict'`, or `'none'` |

`cookieSameSite: 'none'` is required for cross-site browser clients. It forces `Secure` on, and removes
the cross-site protection that keeps a permissive CORS setup contained — pair it with an explicit
`origins` allowlist rather than `corsAllowAll`.

### Cookies behind a proxy

`cookieSecure: 'auto'` decides `Secure` from the connection the server actually observes. It reads
`x-forwarded-proto` **only when `trustProxy` is enabled**, because `trustProxy` is the single switch
declaring forwarded headers trustworthy — a client reaching the origin directly can set any header it
likes, so `'auto'` deliberately does not honour it by default.

The consequence: with a TLS-terminating reverse proxy and the default `trustProxy: false`, the server
sees plain HTTP and issues auth cookies **without** `Secure`. ApiCore warns at startup when it detects
this combination.

| Deployment | Required settings |
| --- | --- |
| Direct HTTPS (no proxy) | Defaults are correct |
| Behind one reverse proxy | `trustProxy: 1` |
| Behind N chained proxies | `trustProxy: N` |
| Proxy depth unknown or variable | `cookieSecure: true` |
| Local HTTP development | `devMode: true` |

Set `trustProxy` regardless — it also drives client-IP resolution, which the auth rate limiter and
every `getClientIp()` caller depend on.

## Tokens and authentication

| Option | Default | Description |
| --- | --- | --- |
| `accessSecret` | `''` | JWT signing secret for access tokens (required for auth) |
| `refreshSecret` | `''` | JWT signing secret for refresh tokens. Must differ from `accessSecret` |
| `accessExpiry` | 15 minutes | Access token lifetime in seconds |
| `refreshExpiry` | ~30 days | Refresh token lifetime in seconds |
| `sessionRefreshExpiry` | 24 hours | Refresh lifetime when the client opts for session-only cookies |
| `authApi` | `false` | Convenience toggle for mounting auth-specific modules |
| `validateTokens` | `false` | Enforce stored-token validation for every JWT request. API keys stay stateless |
| `refreshMaybe` | `false` | Let `auth: maybe` routes attempt cookie-based refresh |
| `tokenStore` | unset | Application-provided `TokenStore` adapter |

## API keys

| Option | Default | Description |
| --- | --- | --- |
| `apiKeyEnabled` | `false` | Allow API-key lookups on routes not typed `apikey` |
| `apiKeyPrefix` | `''` | Bearer-token prefix. Empty accepts raw key values |
| `apiKeyStore` | unset | Application-provided `ApiKeyStore` adapter |
| `tokenParam` | `''` | Request field name used as a token fallback when Bearer is missing |
| `tokenParamLocation` | `body` | Where `tokenParam` is read from: `body`, `query`, or `body-query` |

## Signed requests

| Option | Default | Description |
| --- | --- | --- |
| `signer` | unset | Default `RequestSigner` required for incoming `api()` routes |

```ts
signer: new HmacSigner({
	secret: process.env.API_REQUEST_SECRET,
	in: 'header',
	signature: 'x-apicore-signature',
	timestamp: 'x-apicore-timestamp',
	maxAge: 300
})
```

The server signer applies only to routes mounted through `api()`. CORS preflight and framework routes such as ping, Swagger, static files, and unmatched paths do not inherit it. A module can override it with `new ApiModule({ signer })` or `server.api(module, { signer })`. A route can use another signer or `false`.

Shared secrets belong in trusted server-to-server clients, not browser code. Use `signer: false` for browser-entered OAuth callbacks and other routes whose callers cannot sign. Multipart requests are rejected on signed routes because file bytes are not part of this format.

`in` defaults to `header` and can be changed to `parameter`. Parameter transport uses the query string for GET and DELETE, and the top-level JSON or URL-encoded body for other methods. Signature and timestamp fields are removed from query and body before validation, hashing, and handlers.

Query and body parameters are separate canonical sections, so moving a value invalidates the signature. Each section sorts by parameter name and then content using UTF-16 code-unit order. Repeated values remain separate. Names and values use `URLSearchParams` encoding, where spaces become `+`. Nested non-string values use JSON with recursively sorted object keys.

The exact input is `METHOD\npath\ntimestamp\nqueryParams\nbodyParams`. For example, `POST /items?b=2&a=1` with `{"c":"hello world"}` signs:

```text
POST
/items
1723377600
a=1&b=2
c=hello+world
```

An identical request can replay inside `maxAge` (300 seconds by default). Non-idempotent endpoints need their own nonce or idempotency-key storage. Parameter transport exposes GET/DELETE signatures to URL logs, so headers are preferred.

`RequestSigner` owns canonicalization, transport, timestamp, and expiry handling. Extend it and implement `createSignature()` for another scheme. `HmacSigner` implements HMAC-SHA256 with constant-time verification.

## Uploads

| Option | Default | Description |
| --- | --- | --- |
| `multipartEnabled` | `false` | Parse `multipart/form-data` for `ApiModule` routes |
| `uploadPath` | `./uploads` | Upload root; MIME and TUS use the `mime` and `tus` subdirectories |
| `uploadMax` | 30 MiB | Maximum upload size in bytes |
| `uploadMinDiskFreeMB` | unset | Minimum free disk space for file-backed uploads |
| `uploadMinDiskFreePercent` | unset | Minimum free disk percentage for file-backed uploads |
| `uploadCleanup` | `lazy` | Orphan cleanup mode: `lazy`, `interval`, or `off` |
| `uploadCleanupIntervalSeconds` | 15 minutes | Minimum time between cleanup runs |
| `uploadOrphanExpirySeconds` | 24 hours | Age at which staged files and incomplete uploads are orphaned |

See [uploads](uploads/README.md) for the full upload and TUS documentation.

## Operations and diagnostics

| Option | Default | Description |
| --- | --- | --- |
| `trustProxy` | `false` | Trust in proxy headers: `false` = socket only, `true` = trust all, number = trust N rightmost entries |
| `debug` | `false` | Log request payloads and route registration |
| `devMode` | `false` | Environment-specific logic. Also relaxes production defaults — never enable in production |
| `hydrateGetBody` | `true` | Copy GET query parameters onto `req.body` |
| `apiVersion` | `''` | Version string reported by `GET <apiBasePath>/v1/ping` |
| `minClientVersion` | `''` | Minimum client version reported by ping, so clients can self-gate |

`devMode` implies `corsAllowAll` when `origins` is empty and suppresses the startup warnings below.

## Startup warnings

Outside `devMode`, `ApiServer` warns at construction when:

- `authApi` is on but `accessSecret` or `refreshSecret` is empty.
- `accessSecret` and `refreshSecret` are identical. Both token types carry the same claims, so one
  secret makes each verifiable as the other. Always use two distinct secrets.
- `corsAllowAll` is on with an empty `origins` list.
- `cookieSecure` is `'auto'` while `trustProxy` is `false`.

## Application quotas and security events

```ts
const server = new ApiServer({
	rateLimits: {
		policies: {
			ip: { limit: 120, windowMs: 60_000, identity: 'ip' },
			search: { limit: 30, windowMs: 60_000, identity: 'user' }
		},
		global: 'ip',
		maxKeys: 10_000
		// store: customStore // implements RateLimitStore
	},
	securityEventSink: (record) => dedicatedLogger.write(JSON.stringify(record) + '\n')
});
```

Set `rateLimit: 'search'` on an `ApiModule.defineRoutes()` route. `rateLimit: false` omits only its route policy. Routes without a policy still consume the configured global quota. No quotas apply unless configured.

Global quotas run before authentication in `executeApiRequest`; route quotas run after authentication/authorization and before the handler. IP policies use the trust-proxy-aware `getClientIp()`; user policies use `getRealUid()`, including during impersonation. Missing identities return 401. Global user policies and unknown policies are rejected during setup. Restrict `trustProxy` to trusted proxy hops; arbitrary forwarded headers are not trusted by default.

`await server.rateLimiter.consume('ip', canonicalIp, 5)` supports weighted costs. Identities must be trusted canonical strings, never raw user-supplied headers. `RateLimitStore.consume(key, { limit, windowMs }, cost = 1)` returns `Promise<RateLimitDecision>` with `{ allowed, limit, remaining, retryAfterSec }`. Limits, windows, costs, and `maxKeys` must be positive safe integers. Allowed decisions have `retryAfterSec: 0`; rejected decisions have `remaining: 0` and a rounded-up retry delay. Policy/identity keys use JSON tuple encoding to avoid namespace collisions.

The default `MemoryRateLimitStore` starts a fixed window on first use, counts rejected attempts, and expires accessed entries lazily without extending windows. Its bounded map evicts the oldest-used key, including after rejected attempts. Eviction can reset quotas under key floods. Counters are process-local and reset on restart; use a custom store for multiple workers or instances. External adapters must return rejected decisions for quota denial and reject promises for backend failures; consumption, TTLs, and namespaces must remain atomic and consistent across instances.

Denied requests return `ApiError(429)` with `data.retryAfterSec`. Backend failures propagate and fail closed through the normal error handler. No `Retry-After` header is added. These quotas cover only the ApiModule pipeline, after Fastify parsing/validation; native Fastify routes, sockets, and custom handlers are outside it. This does not replace edge DDoS protections.

`await server.securityEvents.report('auth.login.failed', { ip })` sends `{ ...fields, ts, event }` to the optional sink. `ts` is an ISO timestamp; neither reserved field can be overridden. The service awaits the sink and propagates sink failures. There is no implicit console/file output, auth event emission, counter, or ban. Callers must select safe fields; never include credentials, OTPs, tokens, or full cookies. The application owns sink redaction, JSONL output and rotation; Fail2ban or another processor owns failure thresholds and bans.

The existing `FixedWindowRateLimiter` and `createAuthRateLimitHook` are unchanged. The new exported `RateLimitDecision` requires all four fields; the old two-field type is available as `LegacyRateLimitDecision`.
