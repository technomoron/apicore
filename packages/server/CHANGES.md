# Changes

Version 1.1.0 (2026-10-22)
-------------------
* Add an optional generic OAuth authorization server with discovery, browser authorization, S256 PKCE, form-encoded token exchange, resource-bound tokens and refresh rotation.
* Add protected-resource metadata and access-token validation helpers while preserving the existing JSON auth API.
* Add optional password/consent login with a second-factor hook, RFC 6238 verification, confidential service-account grants and private persistent sessions.
* Implementation, documentation and tests were assisted by Codex, OpenAI.

v1.0.0 (2026-08-11)
-------------------
* Initial public release of the Fastify API framework.
* Includes modular authentication, JWT sessions, OAuth, passkeys, API keys, uploads, OpenAPI output, and Sequelize adapters.
* Includes configurable request signing with extensible signers and HMAC-SHA256 support, plus signed raw outbound HTTP requests.
* Requires Node 24 or newer.
