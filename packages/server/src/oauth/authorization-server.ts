import { createHash, randomUUID } from 'node:crypto';

import type { ApiServer } from '../apicore-server.js';
import type { OAuthClient } from './types.js';
import type { AuthIdentifier } from '../auth-api/types.js';
import type { FastifyReply, FastifyRequest } from 'fastify';

export interface OAuthAuthorizationContext {
	request: FastifyRequest;
	reply: FastifyReply;
	client: OAuthClient;
	scopes: readonly string[];
	resources: readonly string[];
}

export interface OAuthGrantContext {
	userId: string;
	clientId: string;
	scopes: string[];
	resources: string[];
}

export interface OAuthAuthorizationServerOptions {
	/** Public HTTPS issuer, configured explicitly rather than derived from request headers. */
	issuer: string;
	resources: string[];
	scopes?: string[];
	/** Separate signing keys keep these grants isolated from ordinary login sessions. */
	accessSecret: string;
	refreshSecret: string;
	accessExpiry?: number;
	refreshExpiry?: number;
	/** Opt-in confidential service clients mapped to existing service-account users. */
	serviceAccounts?: Record<string, AuthIdentifier>;
	/** Application policy applied to every issuance, including refresh and service grants. */
	validateGrant?: (grant: OAuthGrantContext) => Promise<boolean> | boolean;
	/**
	 * Authenticate the browser user and obtain consent. Return false to deny, or
	 * send a login/consent response and return undefined to pause authorization.
	 * Never return an identity taken directly from untrusted request parameters.
	 */
	authorize: (
		context: OAuthAuthorizationContext
	) => Promise<{ userId: AuthIdentifier } | false | void> | { userId: AuthIdentifier } | false | void;
	rateLimit?: (request: FastifyRequest, endpoint: 'authorize' | 'token') => Promise<void> | void;
}

export interface OAuthAccessToken {
	iss: string;
	aud: string[];
	sub: string;
	client_id: string;
	scope: string;
	jti: string;
	exp: number;
	token_use: 'access';
}

type Grant = { userId: string; clientId: string; scopes: string[]; resources: string[] };
type RefreshClaims = Omit<OAuthAccessToken, 'token_use'> & { token_use: 'refresh' };

/** An OAuth protocol error safe to return to clients. */
export class OAuthProtocolError extends Error {
	constructor(
		public readonly error: string,
		description: string,
		public readonly status = 400
	) {
		super(description);
	}
}

function invalid(description: string): never {
	throw new OAuthProtocolError('invalid_request', description);
}

function required(params: URLSearchParams, name: string): string {
	const value = params.get(name);
	if (!value) invalid(name + ' is required');
	return value;
}

function validateParameters(params: URLSearchParams): void {
	for (const name of new Set(params.keys())) {
		if (name !== 'resource' && params.getAll(name).length > 1) invalid('Repeated parameter: ' + name);
	}
}

function validResource(value: string): boolean {
	try {
		const url = new URL(value);
		return !value.includes('#') && !url.username && !url.password;
	} catch {
		return false;
	}
}

function scopeList(value: string | null): string[] {
	if (value === null || value === '') return [];
	if (!/^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$/.test(value)) {
		throw new OAuthProtocolError('invalid_scope', 'Invalid scope syntax');
	}
	return [...new Set(value.split(' '))];
}

function selectResources(params: URLSearchParams, allowed: readonly string[]): string[] {
	const requested = [...new Set(params.getAll('resource'))];
	if (requested.some((resource) => !validResource(resource) || !allowed.includes(resource))) {
		throw new OAuthProtocolError('invalid_target', 'Requested resource is not permitted');
	}
	return requested.length ? requested : [...allowed];
}

function selectScopes(params: URLSearchParams, allowed: readonly string[]): string[] {
	const scopes = params.has('scope') ? scopeList(params.get('scope')) : [...allowed];
	if (scopes.some((scope) => !allowed.includes(scope))) {
		throw new OAuthProtocolError('invalid_scope', 'Requested scope is not permitted');
	}
	return scopes;
}

function authorizationRedirect(uri: string, values: Record<string, string | undefined>): string {
	const redirect = new URL(uri);
	for (const [key, value] of Object.entries(values)) {
		if (value !== undefined) redirect.searchParams.set(key, value);
	}
	return redirect.toString();
}

/**
 * Optional standard OAuth HTTP endpoints using ApiServer's existing client,
 * authorization-code and token stores. Does not change AuthModule's JSON API.
 */
export class OAuthAuthorizationServer {
	private readonly issuer: string;
	private readonly path: string;
	private readonly resources: string[];
	private readonly scopes: string[];
	private readonly accessExpiry: number;
	private readonly refreshExpiry: number;

	constructor(
		private readonly server: ApiServer,
		private readonly options: OAuthAuthorizationServerOptions
	) {
		const issuer = new URL(options.issuer);
		if (
			issuer.protocol !== 'https:' ||
			options.issuer.trim() !== options.issuer ||
			options.issuer.includes('?') ||
			options.issuer.includes('#') ||
			issuer.username ||
			issuer.password
		) {
			throw new Error('OAuth issuer must be an HTTPS URL without credentials, query or fragment');
		}
		this.issuer = options.issuer;
		this.path = issuer.pathname.replace(/\/$/, '');
		this.resources = [...new Set(options.resources)];
		this.scopes = [...new Set(options.scopes ?? [])];
		if (!this.resources.length || this.resources.some((resource) => !validResource(resource))) {
			throw new Error('OAuth resources must contain absolute resource URIs without fragments or credentials');
		}
		for (const scope of this.scopes) {
			if (scopeList(scope).length !== 1) throw new Error('Invalid supported OAuth scope');
		}
		const keys = [options.accessSecret, options.refreshSecret];
		if (keys.some((key) => typeof key !== 'string' || key.length < 32) || keys[0] === keys[1]) {
			throw new Error('OAuth access and refresh secrets must be distinct keys of at least 32 characters');
		}
		if (keys.some((key) => key === server.config.accessSecret || key === server.config.refreshSecret)) {
			throw new Error('OAuth signing keys must differ from ordinary login signing keys');
		}
		if (typeof options.authorize !== 'function') throw new Error('An OAuth login and consent handler is required');
		this.accessExpiry = options.accessExpiry ?? 900;
		this.refreshExpiry = options.refreshExpiry ?? 30 * 24 * 60 * 60;
		for (const expiry of [this.accessExpiry, this.refreshExpiry]) {
			if (!Number.isSafeInteger(expiry) || expiry <= 0)
				throw new Error('OAuth token lifetimes must be positive integers');
		}
	}

	/** Register before ApiServer starts accepting requests. */
	public register(): this {
		this.server.registerOpenApiPathPrefix('/oauth', this.path || '/');
		this.server.registerOpenApiPathPrefix(
			'/.well-known/oauth-authorization-server/oauth',
			'/.well-known/oauth-authorization-server' + this.path
		);
		void this.server.fastify.register(async (app) => {
			app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
				done(null, new URLSearchParams(body as string));
			});
			app.setErrorHandler((_error, _request, reply) => {
				this.sendError(reply, new OAuthProtocolError('invalid_request', 'Invalid OAuth request'));
			});
			app.get('/.well-known/oauth-authorization-server' + this.path, async () => this.metadata());
			app.get(this.path + '/authorize', async (request, reply) => this.authorize(request, reply));
			app.post(this.path + '/token', async (request, reply) => {
				reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
				try {
					await this.options.rateLimit?.(request, 'token');
					if (!(request.body instanceof URLSearchParams)) invalid('Use application/x-www-form-urlencoded');
					return await this.exchange(request, request.body);
				} catch (error) {
					return this.sendError(reply, error);
				}
			});
		});
		return this;
	}

	public metadata(): Record<string, unknown> {
		const origin = new URL(this.issuer).origin;
		return {
			issuer: this.issuer,
			authorization_endpoint: origin + this.path + '/authorize',
			token_endpoint: origin + this.path + '/token',
			response_types_supported: ['code'],
			grant_types_supported: ['authorization_code', 'refresh_token', ...(Object.keys(this.options.serviceAccounts ?? {}).length ? ['client_credentials'] : [])],
			code_challenge_methods_supported: ['S256'],
			token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
			scopes_supported: [...this.scopes],
			authorization_response_iss_parameter_supported: true
		};
	}

	/** RFC 9728 document for an application to serve at its protected resource. */
	public resourceMetadata(resource: string): Record<string, unknown> {
		if (!this.resources.includes(resource)) throw new Error('Unknown OAuth resource');
		return {
			resource,
			authorization_servers: [this.issuer],
			scopes_supported: [...this.scopes],
			bearer_methods_supported: ['header']
		};
	}

	/** Validate audience, issuer, token use, expiry, revocation and required scopes. */
	public async verifyAccessToken(token: string, resource: string, scopes: string[] = []): Promise<OAuthAccessToken> {
		if (!this.resources.includes(resource)) throw new OAuthProtocolError('invalid_token', 'Unknown resource', 401);
		const result = this.server.jwtVerify<OAuthAccessToken>(token, this.options.accessSecret, {
			algorithms: ['HS256'],
			issuer: this.issuer,
			audience: resource
		});
		const claims = result.data;
		if (!result.success || !claims || claims.token_use !== 'access' || !this.validClaims(claims)) {
			throw new OAuthProtocolError('invalid_token', 'Invalid or expired access token', 401);
		}
		const stored = await this.server.getToken({ accessToken: token });
		if (
			!stored ||
			stored.userId !== claims.sub ||
			stored.clientId !== claims.client_id ||
			stored.status === 'revoked'
		) {
			throw new OAuthProtocolError('invalid_token', 'Access token is no longer active', 401);
		}
		const granted = scopeList(claims.scope);
		if (scopes.some((scope) => !granted.includes(scope))) {
			throw new OAuthProtocolError('insufficient_scope', 'Required scope was not granted', 403);
		}
		return claims;
	}

	private validClaims(claims: OAuthAccessToken | RefreshClaims): boolean {
		return (
			typeof claims.sub === 'string' &&
			claims.sub.length > 0 &&
			typeof claims.client_id === 'string' &&
			typeof claims.scope === 'string' &&
			Array.isArray(claims.aud) &&
			claims.aud.length > 0 &&
			claims.aud.every((aud) => typeof aud === 'string') &&
			typeof claims.exp === 'number' &&
			typeof claims.jti === 'string'
		);
	}

	private sendError(reply: FastifyReply, error: unknown): FastifyReply {
		const failure =
			error instanceof OAuthProtocolError
				? error
				: new OAuthProtocolError('server_error', 'Unable to complete OAuth request', 500);
		if (failure.error === 'invalid_client') reply.header('WWW-Authenticate', 'Basic realm="oauth"');
		return reply
			.code(failure.status)
			.header('Cache-Control', 'no-store')
			.header('Pragma', 'no-cache')
			.send({ error: failure.error, error_description: failure.message });
	}

	private async authorize(request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply> {
		let redirectUri: string | undefined;
		let state: string | undefined;
		try {
			await this.options.rateLimit?.(request, 'authorize');
			const params = new URL(request.url, this.issuer).searchParams;
			validateParameters(params);
			const client = await this.server.getClient(required(params, 'client_id'));
			const requestedRedirect = required(params, 'redirect_uri');
			if (!client || !client.redirectUris.includes(requestedRedirect)) invalid('Unknown client or redirect_uri');
			const uri = new URL(requestedRedirect);
			if (requestedRedirect.includes('#') || ['javascript:', 'data:', 'file:'].includes(uri.protocol))
				invalid('Invalid redirect_uri');
			redirectUri = requestedRedirect;
			state = params.get('state') ?? undefined;
			if (required(params, 'response_type') !== 'code') {
				throw new OAuthProtocolError('unsupported_response_type', 'Only response_type=code is supported');
			}
			const challenge = required(params, 'code_challenge');
			if (params.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
				invalid('S256 PKCE is required');
			}
			const scopes = selectScopes(
				params,
				(client.scope ?? []).filter((scope) => this.scopes.includes(scope))
			);
			const resources = selectResources(params, this.resources);
			const decision = await this.options.authorize({
				request,
				reply,
				client,
				scopes: Object.freeze([...scopes]),
				resources: Object.freeze([...resources])
			});
			if (reply.sent) return reply;
			if (decision === false) throw new OAuthProtocolError('access_denied', 'Authorization was declined');
			if (!decision || !['string', 'number'].includes(typeof decision.userId) || !String(decision.userId)) {
				throw new Error('Authorization handler did not provide an authenticated user');
			}
			if (!(await this.server.getUser(decision.userId))) throw new Error('Authenticated user no longer exists');
			const record = await this.server.createAuthCode({
				clientId: client.clientId,
				userId: decision.userId,
				redirectUri,
				scope: scopes,
				codeChallenge: challenge,
				codeChallengeMethod: 'S256',
				expiresInSeconds: 300,
				metadata: { oauthIssuer: this.issuer, oauthResources: resources }
			});
			return reply
				.header('Cache-Control', 'no-store')
				.header('Referrer-Policy', 'no-referrer')
				.redirect(authorizationRedirect(redirectUri, { code: record.code, state, iss: this.issuer }));
		} catch (error) {
			if (reply.sent) return reply;
			if (!redirectUri) return this.sendError(reply, error);
			const failure =
				error instanceof OAuthProtocolError
					? error
					: new OAuthProtocolError('server_error', 'Unable to complete authorization');
			return reply.header('Cache-Control', 'no-store').redirect(
				authorizationRedirect(redirectUri, {
					error: failure.error,
					error_description: failure.message,
					state,
					iss: this.issuer
				})
			);
		}
	}

	private async authenticateClient(request: FastifyRequest, params: URLSearchParams): Promise<OAuthClient> {
		let clientId = params.get('client_id');
		let secret = params.get('client_secret');
		const authorization = request.headers.authorization;
		if (authorization !== undefined) {
			if (!authorization.startsWith('Basic ') || secret !== null)
				invalid('Conflicting client authentication methods');
			const decoded = Buffer.from(authorization.slice(6), 'base64').toString('utf8');
			const separator = decoded.indexOf(':');
			if (separator < 0) invalid('Invalid client authentication');
			let headerId: string;
			try {
				headerId = decodeURIComponent(decoded.slice(0, separator).replace(/\+/g, ' '));
				secret = decodeURIComponent(decoded.slice(separator + 1).replace(/\+/g, ' '));
			} catch {
				invalid('Invalid client authentication');
			}
			if (clientId !== null && clientId !== headerId) invalid('Conflicting client identifiers');
			clientId = headerId;
		}
		const client = clientId ? await this.server.getClient(clientId) : null;
		if (
			!client ||
			((client.hasSecret ?? false)
				? !secret || !(await this.server.verifyClientSecret(client, secret))
				: secret !== null)
		) {
			throw new OAuthProtocolError('invalid_client', 'Client authentication failed', 401);
		}
		return client;
	}

	private async exchange(request: FastifyRequest, params: URLSearchParams): Promise<Record<string, unknown>> {
		validateParameters(params);
		const client = await this.authenticateClient(request, params);
		const grantType = required(params, 'grant_type');
		if (grantType === 'client_credentials') {
			const account = this.options.serviceAccounts?.[client.clientId];
			if (!(client.hasSecret ?? false) || account === undefined) {
				throw new OAuthProtocolError('unauthorized_client', 'Service-account grant is not enabled for this client');
			}
			const pair = await this.issue({ userId: String(account), clientId: client.clientId,
				scopes: selectScopes(params, (client.scope ?? []).filter((scope) => this.scopes.includes(scope))),
				resources: selectResources(params, this.resources) }, this.accessExpiry);
			const { refresh_token: _refresh, ...accessOnly } = pair;
			void _refresh;
			return accessOnly;
		}
		if (grantType === 'authorization_code') {
			const redirectUri = required(params, 'redirect_uri');
			if (!client.redirectUris.includes(redirectUri)) invalid('Invalid redirect_uri');
			const verifier = required(params, 'code_verifier');
			if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) invalid('Invalid PKCE verifier');
			const record = await this.server.consumeAuthCode(required(params, 'code'), client.clientId);
			if (
				!record ||
				record.expiresAt.getTime() <= Date.now() ||
				record.redirectUri !== redirectUri ||
				record.codeChallengeMethod !== 'S256' ||
				record.codeChallenge !== createHash('sha256').update(verifier).digest('base64url') ||
				record.metadata?.oauthIssuer !== this.issuer
			) {
				throw new OAuthProtocolError('invalid_grant', 'Invalid or expired authorization code');
			}
			const resources = record.metadata.oauthResources;
			if (
				!Array.isArray(resources) ||
				!resources.length ||
				!resources.every((r) => typeof r === 'string' && this.resources.includes(r))
			) {
				throw new OAuthProtocolError('invalid_grant', 'Invalid authorization grant');
			}
			if (params.has('scope')) invalid('Scope cannot be changed during code exchange');
			return this.issue(
				{
					userId: String(record.userId),
					clientId: client.clientId,
					scopes: record.scope ?? [],
					resources: selectResources(params, resources)
				},
				this.refreshExpiry
			);
		}
		if (grantType !== 'refresh_token') {
			throw new OAuthProtocolError('unsupported_grant_type', 'Unsupported grant type');
		}
		const token = required(params, 'refresh_token');
		const result = this.server.jwtVerify<RefreshClaims>(token, this.options.refreshSecret, {
			algorithms: ['HS256'],
			issuer: this.issuer
		});
		const claims = result.data;
		if (
			!result.success ||
			!claims ||
			claims.token_use !== 'refresh' ||
			!this.validClaims(claims) ||
			claims.client_id !== client.clientId ||
			claims.aud.some((resource) => !this.resources.includes(resource))
		) {
			throw new OAuthProtocolError('invalid_grant', 'Invalid or expired refresh token');
		}
		const stored = await this.server.getToken({ refreshToken: token, clientId: client.clientId });
		if (!stored || stored.userId !== claims.sub || stored.status === 'revoked') {
			throw new OAuthProtocolError('invalid_grant', 'Refresh token is no longer active');
		}
		const grant = {
			userId: claims.sub,
			clientId: client.clientId,
			scopes: selectScopes(params, scopeList(claims.scope)),
			resources: selectResources(params, claims.aud)
		};
		const lifetime = claims.exp - Math.floor(Date.now() / 1000);
		if (lifetime <= 0 || !(await this.server.getUser(grant.userId))) {
			throw new OAuthProtocolError('invalid_grant', 'Grant is no longer active');
		}
		// Every validation precedes consumption. Concurrent replay has one winner.
		if (!(await this.server.deleteToken({ refreshToken: token }))) {
			throw new OAuthProtocolError('invalid_grant', 'Refresh token was already consumed');
		}
		return this.issue(grant, lifetime);
	}

	private async issue(grant: Grant, refreshLifetime: number): Promise<Record<string, unknown>> {
		if (!(await this.server.getUser(grant.userId)))
			throw new OAuthProtocolError('invalid_grant', 'User no longer exists');
		if (this.options.validateGrant && !(await this.options.validateGrant(grant))) throw new OAuthProtocolError('invalid_grant', 'Grant is no longer permitted');
		const accessLifetime = Math.min(this.accessExpiry, refreshLifetime);
		const payload = {
			iss: this.issuer,
			aud: grant.resources,
			sub: grant.userId,
			client_id: grant.clientId,
			scope: grant.scopes.join(' '),
			jti: randomUUID()
		};
		const access = this.server.jwtSign(
			{ ...payload, token_use: 'access' },
			this.options.accessSecret,
			accessLifetime
		);
		const refresh = this.server.jwtSign(
			{ ...payload, jti: randomUUID(), token_use: 'refresh' },
			this.options.refreshSecret,
			refreshLifetime
		);
		if (!access.success || !access.token || !refresh.success || !refresh.token)
			throw new Error('Token signing failed');
		await this.server.storeToken({
			userId: grant.userId,
			clientId: grant.clientId,
			scope: grant.scopes,
			loginType: 'oauth-standard',
			sessionId: randomUUID(),
			fingerprint: payload.jti,
			accessToken: access.token,
			refreshToken: refresh.token,
			expires: new Date(Date.now() + refreshLifetime * 1000),
			issuedAt: new Date(),
			status: 'active'
		});
		return {
			access_token: access.token,
			refresh_token: refresh.token,
			token_type: 'Bearer',
			expires_in: accessLifetime,
			scope: grant.scopes.join(' ')
		};
	}
}
