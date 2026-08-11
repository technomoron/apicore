# OAuth module

`AuthModule` can act as an OAuth authorization server for registered clients and can expose application-defined external-provider start and callback routes.

## Authorization-server storage

Configure an auth adapter that implements OAuth client and authorization-code storage. `MemAuthStore` includes an in-memory OAuth store; `SqlAuthStore` and `SequelizeOAuthStore` provide persistent options.

The following routes mount when the required storage methods are available:

| Method and path | Authentication | Purpose |
| --- | --- | --- |
| `POST /v1/oauth2/authorize` | Optional | Validate a client request and issue an authorization code |
| `POST /v1/oauth2/token` | None | Exchange an authorization code or refresh token |

The token endpoint supports `authorization_code` and `refresh_token` grants. Confidential clients must authenticate, redirect URIs must match the client record, and public clients must use PKCE. Use `S256`; plain PKCE is disabled unless `allowInsecurePkcePlain` is explicitly enabled.

The authorize route accepts user credentials, a configured refresh cookie, or a `refreshToken` in its JSON body. Sending refresh tokens in cookies is preferred for browser applications because it keeps them out of application JavaScript.

## External providers

If an `ApiServer` subclass implements `initiateOAuth()` and `completeOAuth()`, these routes are also mounted:

| Method and path | Authentication | Purpose |
| --- | --- | --- |
| `POST /v1/oauth2/:provider/start` | None | Begin an application-defined provider flow |
| `POST /v1/oauth2/:provider/callback` | None | Complete the provider flow |

The application owns provider discovery, state validation, token exchange, account linking, and the decision to issue ApiCore tokens.

## Client records

An OAuth client contains a stable `clientId`, allowed redirect URIs, optional allowed scopes, and optional confidential-client credentials. Requested scopes must all appear in the client record. A missing or empty scope list permits no requested scopes; when a client has allowed scopes and the request omits `scope`, all of its allowed scopes are used. Do not return stored client secrets from administration or diagnostic APIs.
