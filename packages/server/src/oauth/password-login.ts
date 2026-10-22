import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import type { ApiServer } from '../apicore-server.js';
import type { OAuthAuthorizationContext } from './authorization-server.js';
import type { AuthIdentifier } from '../auth-api/types.js';

interface PendingLogin {
	url: string;
	expires: number;
	csrf: string;
	attempts: number;
	scopes: readonly string[];
	resources: readonly string[];
	clientId: string;
}

export interface OAuthPasswordLoginOptions {
	issuer: string;
	/** Enforce user/client/resource policy before completing consent. */
	allow: (
		userId: AuthIdentifier,
		clientId: string,
		scopes: readonly string[],
		resources: readonly string[]
	) => Promise<boolean> | boolean;
	/** Optional second factor. The application must persist any replay counter. */
	verifySecondFactor?: (user: unknown, code: string) => Promise<boolean> | boolean;
	maxPending?: number;
}

const escape = (value: string) =>
	value.replace(
		/[&<>"']/g,
		(character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!
	);
const nonce = () => randomBytes(32).toString('base64url');
const equal = (left: string, right: string) =>
	Buffer.byteLength(left) === Buffer.byteLength(right) && timingSafeEqual(Buffer.from(left), Buffer.from(right));

/** Optional password/second-factor login and explicit OAuth consent form. */
export class OAuthPasswordLogin {
	private readonly pending = new Map<string, PendingLogin>();
	private readonly approvals = new Map<string, { userId: AuthIdentifier; url: string; expires: number }>();
	private readonly rates = new Map<string, { expires: number; count: number }>();
	private readonly cookie: string;
	private readonly path: string;
	constructor(
		private readonly server: ApiServer,
		private readonly options: OAuthPasswordLoginOptions
	) {
		const issuer = new URL(options.issuer);
		if (issuer.protocol !== 'https:' || issuer.search || issuer.hash)
			throw new Error('Login issuer must use HTTPS');
		this.path = issuer.pathname.replace(/\/$/, '');
		this.cookie = 'apicore_oauth_' + createHash('sha256').update(options.issuer).digest('hex').slice(0, 12);
	}
	private cleanup(): void {
		for (const map of [this.pending, this.approvals, this.rates]) {
			for (const [key, value] of map) if (value.expires <= Date.now()) map.delete(key);
		}
	}
	private page(id: string, pending: PendingLogin, error = ''): string {
		return (
			'<!doctype html><html><head><meta charset="utf-8"><title>Authorize access</title></head><body>' +
			'<h1>Authorize access</h1><p>Client: ' +
			escape(pending.clientId) +
			'</p><p>Permissions: ' +
			escape(pending.scopes.join(', ')) +
			'</p><p>Resources: ' +
			escape(pending.resources.join(', ')) +
			'</p>' +
			(error ? '<p role="alert">' + escape(error) + '</p>' : '') +
			'<form method="post" action="' +
			escape(this.path + '/login') +
			'">' +
			'<input type="hidden" name="request" value="' +
			id +
			'"><input type="hidden" name="csrf" value="' +
			pending.csrf +
			'">' +
			'<label>Username <input name="login" autocomplete="username" required maxlength="200"></label>' +
			'<label>Password <input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label>' +
			(this.options.verifySecondFactor
				? '<label>Authenticator code <input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="8"></label>'
				: '') +
			'<button type="submit">Sign in and allow access</button></form></body></html>'
		);
	}
	/** Supply this callback as OAuthAuthorizationServerOptions.authorize. */
	public readonly authorize = async (
		context: OAuthAuthorizationContext
	): Promise<{ userId: AuthIdentifier } | void> => {
		this.cleanup();
		const { request, reply } = context;
		const url = new URL(request.url, this.options.issuer);
		const relative = url.pathname + url.search;
		const approvalId = request.cookies[this.cookie + '_approved'];
		const approved = approvalId ? this.approvals.get(approvalId) : undefined;
		if (approved) {
			this.approvals.delete(approvalId!);
			reply.clearCookie(this.cookie + '_approved', {
				path: this.path || '/',
				secure: true,
				httpOnly: true,
				sameSite: 'lax'
			});
			if (
				approved.url === relative &&
				approved.expires > Date.now() &&
				(await this.options.allow(approved.userId, context.client.clientId, context.scopes, context.resources))
			) {
				return { userId: approved.userId };
			}
		}
		if (this.pending.size >= (this.options.maxPending ?? 1000)) {
			reply.code(429).send('Too many pending logins. Try again later.');
			return;
		}
		const id = nonce();
		const pending = {
			url: relative,
			csrf: nonce(),
			attempts: 0,
			expires: Date.now() + 300000,
			clientId: context.client.clientId,
			scopes: context.scopes,
			resources: context.resources
		};
		this.pending.set(id, pending);
		reply.setCookie(this.cookie, id, {
			path: this.path || '/',
			secure: true,
			httpOnly: true,
			sameSite: 'lax',
			maxAge: 300
		});
		reply
			.header('Cache-Control', 'no-store')
			.header('Referrer-Policy', 'no-referrer')
			.header('Content-Security-Policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
			.type('text/html')
			.send(this.page(id, pending));
	};
	public register(): this {
		void this.server.fastify.register(async (app) => {
			app.addContentTypeParser(
				'application/x-www-form-urlencoded',
				{ parseAs: 'string', bodyLimit: 8192 },
				(_request, body, done) => done(null, new URLSearchParams(body as string))
			);
			app.post(this.path + '/login', async (request, reply) => {
				this.cleanup();
				reply
					.header('Cache-Control', 'no-store')
					.header('Referrer-Policy', 'no-referrer')
					.header(
						'Content-Security-Policy',
						"default-src 'none'; form-action 'self'; frame-ancestors 'none'"
					);
				const origin = request.headers.origin;
				if (origin && origin !== new URL(this.options.issuer).origin)
					return reply.code(403).send('Invalid login origin');
				const key = request.ip;
				const rate = this.rates.get(key) ?? { expires: Date.now() + 300000, count: 0 };
				rate.count++;
				this.rates.set(key, rate);
				if (rate.count > 20 || this.rates.size > 10000) return reply.code(429).send('Too many login attempts');
				const body = request.body;
				if (
					!(body instanceof URLSearchParams) ||
					[...new Set(body.keys())].some((name) => body.getAll(name).length !== 1)
				) {
					return reply.code(400).send('Invalid login request');
				}
				const id = body.get('request') ?? '';
				const pending = this.pending.get(id);
				if (!pending || request.cookies[this.cookie] !== id || !equal(body.get('csrf') ?? '', pending.csrf)) {
					return reply.code(403).send('Login expired or invalid. Start authorization again.');
				}
				pending.attempts++;
				if (pending.attempts > 5) {
					this.pending.delete(id);
					return reply.code(429).send('Start authorization again');
				}
				const login = body.get('login') ?? '';
				const password = body.get('password') ?? '';
				if (login.length > 200 || password.length > 1024) return reply.code(400).send('Invalid credentials');
				const user = await this.server.getUser(login);
				// A fixed bcrypt hash keeps unknown-user checks on the normal verification path.
				const hash = user
					? this.server.getUserPasswordHash(user)
					: '$2b$12$bklvrVeo9p8HMz2ubRyno.2eTMD7CGgI/mPP1Ruj8TyH4YabyR6MK';
				const passwordValid = await this.server.verifyPassword(password, hash);
				const factorValid =
					user &&
					passwordValid &&
					(!this.options.verifySecondFactor ||
						(await this.options.verifySecondFactor(user, body.get('code') ?? '')));
				if (!user || !passwordValid || !factorValid)
					return reply
						.code(401)
						.type('text/html')
						.send(this.page(id, pending, 'Invalid credentials'));
				const userId = this.server.getUserId(user);
				if (!(await this.options.allow(userId, pending.clientId, pending.scopes, pending.resources))) {
					this.pending.delete(id);
					return reply.code(403).send('Requested access is not permitted');
				}
				this.pending.delete(id);
				if (this.approvals.size >= (this.options.maxPending ?? 1000))
					return reply.code(429).send('Too many pending approvals');
				const approved = nonce();
				this.approvals.set(approved, { userId, url: pending.url, expires: Date.now() + 60000 });
				reply.clearCookie(this.cookie, {
					path: this.path || '/',
					secure: true,
					httpOnly: true,
					sameSite: 'lax'
				});
				reply.setCookie(this.cookie + '_approved', approved, {
					path: this.path || '/',
					secure: true,
					httpOnly: true,
					sameSite: 'lax',
					maxAge: 60
				});
				return reply.redirect(pending.url);
			});
		});
		return this;
	}
}
