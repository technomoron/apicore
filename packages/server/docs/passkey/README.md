# Passkey module

Passkey routes are part of `AuthModule` and are mounted only when the auth adapter provides passkey challenge and verification services.

## Configure passkeys

```ts
import { ApiServer, AuthModule, MemAuthStore } from '@technomoron/apicore-server';

const store = new MemAuthStore({
	passkeys: {
		enabled: true,
		rpId: 'example.com',
		rpName: 'Example',
		origins: ['https://example.com'],
		userVerification: 'preferred'
	}
});

const server = new ApiServer({
	accessSecret: process.env.ACCESS_SECRET,
	refreshSecret: process.env.REFRESH_SECRET
})
	.authStorage(store)
	.api(new AuthModule());
```

Use `SequelizePasskeyStore` or `SqlAuthStore` for persistent credentials and challenges. The relying-party ID and allowed origins must match the browser origin used for registration and authentication.

## Routes

| Method and path | Authentication | Purpose |
| --- | --- | --- |
| `POST /v1/passkeys/challenge` | Conditional | Create registration or authentication options |
| `POST /v1/passkeys/verify` | Conditional | Verify a registration or authentication response |
| `GET /v1/passkeys` | Strict | List the caller’s registered credentials |
| `DELETE /v1/passkeys/:credentialId` | Strict | Delete one owned credential |

Authentication challenges can be public and may omit a login for discoverable credentials. Registration challenges and registration verification require the same authenticated, non-impersonating user as the target account.

## Stored data

The store retains challenge expiry, credential IDs, public keys, counters, transports, backup state, device type, and the owning user ID. Private key material remains on the authenticator and is never sent to the server.
