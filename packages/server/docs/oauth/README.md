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


## Standard OAuth authorization server

`OAuthAuthorizationServer` is an optional standards-facing provider using the existing OAuth client, authorization-code, user and token stores. It provides RFC 8414 discovery, browser authorization-code redirects, S256 PKCE, form-encoded token exchange, RFC 8707 resource indicators and refresh rotation. Existing `AuthModule` JSON routes remain unchanged.

```ts
import { ApiServer, OAuthAuthorizationServer } from '@technomoron/apicore-server';

const server = new ApiServer().authStorage(persistentAuthStore);
const oauth = new OAuthAuthorizationServer(server, {
	issuer: 'https://auth.example.com/oauth',
	resources: ['https://mcp.example.com/mcp'],
	scopes: ['knowledge:read', 'knowledge:write'],
	accessSecret: process.env.OAUTH_ACCESS_SECRET!,
	refreshSecret: process.env.OAUTH_REFRESH_SECRET!,
	authorize: async ({ request, reply, client, scopes, resources }) => {
		// Application-owned: authenticate a browser session, protect the login
		// and consent forms against CSRF, then confirm this user may grant
		// these scopes/resources to this client. Return false to deny.
		const user = await authenticateAndObtainConsent({ request, reply, client, scopes, resources });
		if (reply.sent) return;
		return user ? { userId: user.id } : false;
	}
}).register();
```

The application must provide its own persistent stores, client provisioning, login/consent UI and rate limiter through `rateLimit(request, endpoint)`. The callback must not accept a user identity directly from query parameters. It runs only after client, redirect, PKCE, scope and resource validation. It can send a login page or redirect itself, then return without a decision; no authorization code is issued in that case. An approval must return an existing user id.

Client scopes and provider scopes both restrict authorization. The callback must additionally enforce user/client/resource permissions; OAuth scopes are independent of application project or customer scopes. Client registration is explicit through the existing OAuth store; automatic registration and Client ID Metadata Documents are not implemented.

Configure the public HTTPS issuer explicitly. It is never inferred from Host or forwarded headers. For issuer `https://auth.example.com/oauth`, the provider mounts:

| Method and path                                     | Purpose                                             |
| --------------------------------------------------- | --------------------------------------------------- |
| `GET /.well-known/oauth-authorization-server/oauth` | RFC 8414 discovery                                  |
| `GET /oauth/authorize`                              | Browser authorization and login/consent callback    |
| `POST /oauth/token`                                 | Form-encoded authorization-code or refresh exchange |

Issuer paths such as `/tenant/team` are supported; discovery uses the RFC 8414 path-insertion rule. Register the provider before starting the server. Its protocol responses are raw OAuth JSON and redirects, without the ordinary `ApiResponse` envelope. Runtime OpenAPI output includes only mounted endpoints and uses their configured paths. Token responses and errors disable caching.

All clients use S256 PKCE. Redirect URIs must match a pre-registered value exactly. Authorization codes are single-use and expire after five minutes. The provider supports confidential clients using `client_secret_basic` or `client_secret_post`, and public clients using `none`. Request parameters cannot be repeated except `resource`.

Access and refresh signing keys must each contain at least 32 characters, differ from each other, and differ from ordinary login signing keys. Generate random secrets and keep them outside source control. This isolates OAuth grants from legacy login and refresh routes. Default access lifetime is 900 seconds; refresh lifetime is 30 days, configurable through `accessExpiry` and `refreshExpiry` in seconds. Signing currently uses HS256; the provider does not publish a JWKS endpoint.

Resources must be absolute URIs without fragments or credentials. A missing `resource` grants all provider resources approved by the consent callback; explicitly request one resource for a single-resource grant. Code exchange and refresh may narrow resources, but cannot broaden them. Refresh may also narrow scopes, consumes the old refresh token once, revokes the old access token, and preserves the grant's original expiry. There are no authentication cookies on the protocol token route.

### Protecting a resource

Use `await oauth.verifyAccessToken(token, resource, requiredScopes)` on each protected request. It verifies the signature, issuer, audience, token purpose, expiry, active stored session and required scopes, returning the validated identity and grant. Enforce application permissions after that check. `OAuthProtocolError` carries the protocol `error` and HTTP `status` for the resource handler to translate into its response; include the appropriate `WWW-Authenticate: Bearer` challenge.

`oauth.resourceMetadata(resource)` returns a generic RFC 9728 protected-resource metadata document. The resource application decides where to mount that document and how to advertise it in authentication challenges. An MCP server can use these helpers while retaining ownership of its MCP transport and customer/project permissions. Nginx can terminate HTTPS and proxy to the provider's private listener; it does not replace token or permission checks.

### Optional login, MFA and service accounts

`OAuthPasswordLogin` supplies an optional password and explicit-consent form.
Register it before starting the server, and pass its `authorize` callback to the
provider. Its options require an `allow(userId, clientId, scopes, resources)` policy
check and optionally accept `verifySecondFactor(user, code)`. The form uses bounded,
short-lived server-side requests, secure HttpOnly SameSite cookies, CSRF checks and
rate limits. It never issues an authorization code before credentials, second
factor (when configured), and consent have succeeded. Pending forms and approvals
are intentionally lost on restart. Password storage and enrollment remain the
application's responsibility. The login helper mounts `POST <issuer-path>/login`.

`verifyTotp(base32Secret, code)` implements RFC 6238 SHA-1 verification and returns
the accepted counter, or null. Persist that counter and pass it as `after` on the
next check to prevent replay. Enroll authenticator secrets outside source control.

For machine access, opt in with `serviceAccounts: { clientId: existingUserId }`.
Only confidential clients may use `grant_type=client_credentials`; authenticate
with their registered secret and request explicit scopes and resources. Responses
contain an access token, without a refresh token. The service client obtains a
fresh grant after expiry. Configure `validateGrant(grant)` to recheck application
policy before every issuance, including code exchange, refresh, and service grants.
Protected resources must still check current permissions on every request.

`JsonTokenStore('/private/runtime/sessions.json')` provides atomic private session
persistence for a single server process. The parent directory must be owned by the
service account with mode 0700 and session files use 0600. Set it with
`server.setTokenStore(store)` before registering the provider. It preserves
independent grants and revocations across restart. Files contain credentials;
exclude the entire runtime directory from Git and backups that lack secret access
controls. A database token store remains suitable for multi-process deployments.
