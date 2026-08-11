# Architecture (apicore-server)

This document describes the **implemented** architecture of the
`@technomoron/apicore-server` package.

## Package Structure

```
src/
  apicore-server.ts      Core Fastify server, auth pipeline, JWT helpers, ApiRequest/ApiResponse
  api-module.ts            Base class for feature modules (namespace, defineRoutes, checkConfig)
  index.ts                 Public export surface

  auth-api/
    types.ts               AuthAdapter interface, AuthIdentifier type
    storage.ts             BaseAuthAdapter (default no-op implementations)
    module.ts              BaseAuthModule / AuthProviderModule interface
    auth-module.ts         Full-featured AuthModule (login, logout, refresh, me, passkeys, OAuth, impersonation)
    mem-auth-store.ts      In-memory auth adapter (tests/dev)
    sql-auth-store.ts      Sequelize-backed auth adapter
    compat-auth-storage.ts CompositeAuthAdapter for bridging legacy storage
    user-id.ts             User ID normalization helpers

  auth-cookie-options.ts   Cookie configuration builder

  base/
    client-info.ts         IP chain extraction, UA parsing, trustProxy support
    error-utils.ts         Error flattening and HTTP status mapping
    request-utils.ts       GET body hydration, object checks

  user/
    base.ts                UserStore abstract class, BcryptHasher
    memory.ts              MemoryUserStore
    sequelize.ts           SequelizeUserStore
    types.ts               BcryptHasherOptions, CreateUserInput, UpdateUserInput, PublicUserMapper

  token/
    base.ts                TokenStore abstract class, JWT sign/verify/decode helpers
    memory.ts              MemoryTokenStore
    sequelize.ts           SequelizeTokenStore
    types.ts               Token, TokenPair, TokenStatus

  passkey/
    base.ts                PasskeyStore abstract class
    memory.ts              MemoryPasskeyStore
    sequelize.ts           SequelizePasskeyStore
    service.ts             PasskeyService (WebAuthn registration + authentication via @simplewebauthn)
    types.ts               PasskeyServiceConfig, StoredPasskeyCredential, challenge types

  oauth/
    base.ts                OAuthStore abstract class
    memory.ts              MemoryOAuthStore
    sequelize.ts           SequelizeOAuthStore
    types.ts               OAuthClient, AuthCodeData, AuthCodeRequest

  upload/
    tus-module.ts          TusUploadModule (TUS 1.0 resumable uploads over Fastify)
    memory.ts              MemoryTusUploadStore
    types.ts               TusMetadata, TusUploadRecord, TusUploadStore

  limiter/
    fixed-window.ts        FixedWindowRateLimiter (in-memory fixed-window counters)
    auth-rate-limiter.ts   createAuthRateLimitHook() for AuthModule rate limiting

  sequelize-utils.ts       Shared Sequelize helpers (table prefix, encoding, ID types)
```

## Key Design Decisions

- **Fastify core**: `ApiServer` wraps Fastify with @fastify/cookie,
  @fastify/cors, and @fastify/multipart. There is no Express dependency.
- **Module composition**: Features are encapsulated as `ApiModule` subclasses.
  Each module declares a namespace, optional config checks, and routes via
  `defineRoutes()`, with either Fastify/Ajv `schema` objects or adapter-driven
  `validator` contracts attached at the route level when validation is needed.
- **Handler contract**: Every handler returns `[status]`, `[status, data]`, or
  `[status, data, message]`. Errors are thrown as `ApiError` and converted to
  JSON envelopes.
- **Orthogonal stores**: User, Token, Passkey, and OAuth concerns have
  independent abstract store classes with memory and Sequelize implementations.
  A single Sequelize instance can back all stores, but they remain independently
  swappable.
- **Password hashing**: `BcryptHasher` is the default. Custom hashers can be
  injected into `UserStore` via the constructor.
- **Auth pipeline**: Authentication resolves Bearer tokens, API keys, cookies,
  and token parameters. Authorization runs after via `authorize()`.
  Impersonation is supported with `canImpersonate` hooks.
- **Rate limiting**: Optional `FixedWindowRateLimiter` with
  `createAuthRateLimitHook()` for per-endpoint rate limiting via
  `AuthModuleOptions.rateLimit`.
- **Proxy trust**: `trustProxy` config controls whether X-Forwarded-For and
  related headers are trusted for IP resolution.

## Store Backends

| Domain   | Memory (tests/dev)   | Sequelize (production) |
| -------- | -------------------- | ---------------------- |
| Users    | MemoryUserStore      | SequelizeUserStore     |
| Tokens   | MemoryTokenStore     | SequelizeTokenStore    |
| Passkeys | MemoryPasskeyStore   | SequelizePasskeyStore  |
| OAuth    | MemoryOAuthStore     | SequelizeOAuthStore    |
| Uploads  | MemoryTusUploadStore | FileTusUploadStore     |

All Sequelize stores accept an injected `Sequelize` instance and never call
`sync()` automatically — lifecycle is caller-owned.
