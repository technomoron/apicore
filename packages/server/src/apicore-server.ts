/**
 * Copyright (c) 2025 Bjørn Erik Jacobsen / Technomoron
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { randomUUID } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { access, mkdir, readFile, readdir, rm, statfs } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

import cookie, { type CookieSerializeOptions } from '@fastify/cookie';
import cors from '@fastify/cors';
import multipart, { type MultipartFile } from '@fastify/multipart';
import fastifyStatic from '@fastify/static';
import fastify, {
	type FastifyContextConfig,
	type FastifyInstance,
	type FastifyReply,
	type FastifyRequest,
	type HTTPMethods
} from 'fastify';

import { ApiModule } from './api-module.js';
import { nullAuthModule } from './auth-api/module.js';
import { nullAuthAdapter } from './auth-api/storage.js';
import { normalizeTokenIdentityQuery, type TokenIdentityQuery } from './auth-api/token-query.js';
import { buildAuthCookieOptions } from './auth-cookie-options.js';
import { ensureClientInfo, type ClientInfo } from './base/client-info.js';
import { redactDebugValue as redactSensitiveDebugValue } from './base/debug.js';
import { createErrorId, logError } from './base/error-log.js';
import { asHttpStatus, guessExceptionText, isApiErrorLike, type ApiErrorLike } from './base/error-utils.js';
import { applyRouteSchemaDefaults, emptyObjectSchema } from './base/json-schema.js';
import { RuntimeOpenApiDocument } from './base/openapi.js';
import { RequestSignatureError, type RequestSigner } from './base/request-signing.js';
import { hydrateGetBody, isPlainObject } from './base/request-utils.js';
import { SecurityEventService, type SecurityEventSink } from './base/security-events.js';
import { RateLimitService, type RateLimitConfig } from './limiter/rate-limit.js';
import {
	TokenStore,
	type JwtDecodeResult,
	type JwtSignPayload,
	type JwtSignResult,
	type JwtVerifyResult
} from './token/base.js';
import { removeStaleUploadFile } from './upload/cleanup.js';

import type { ApiKeyStore } from './api-key/types.js';
import type {
	ApiAuthClass,
	ApiAuthType,
	ApiHandler,
	ApiKey,
	ApiRoute,
	ApiRouteValidatorAdapter,
	ApiRouteValidatorContext
} from './api-module.js';
import type { AuthProviderModule } from './auth-api/module.js';
import type { AuthAdapter, AuthIdentifier } from './auth-api/types.js';
import type { AuthCodeData, AuthCodeRequest, OAuthClient } from './oauth/types.js';
import type {
	PasskeyChallenge,
	PasskeyChallengeParams,
	StoredPasskeyCredential,
	PasskeyVerificationParams,
	PasskeyVerificationResult
} from './passkey/types.js';
import type { Token } from './token/types.js';
import type { TusUploadStore, UploadPurgeResult } from './upload/types.js';
import type { JwtPayload, SignOptions, VerifyOptions } from 'jsonwebtoken';
import type { IncomingMessage } from 'node:http';

export type { JwtPayload, SignOptions, VerifyOptions } from 'jsonwebtoken';
export type { ClientAgentProfile, ClientInfo } from './base/client-info.js';

export interface ApiCookieOptions {
	httpOnly?: boolean;
	secure?: boolean;
	sameSite?: 'lax' | 'strict' | 'none';
	domain?: string;
	path?: string;
	maxAge?: number;
	expires?: Date;
}

export interface ApiUploadedFile {
	fieldname: string;
	originalname: string;
	encoding: string;
	mimetype: string;
	size?: number;
	buffer?: Buffer;
	filepath?: string;
}

export type UploadCleanupMode = 'lazy' | 'interval' | 'off';

export interface UploadPurgeSummary {
	cutoff: string;
	mime: UploadPurgeResult;
	tus: UploadPurgeResult;
	total: UploadPurgeResult;
}

export interface ExtendedReq {
	method: string;
	url: string;
	originalUrl?: string;
	headers: Record<string, string | string[] | undefined>;
	query: Record<string, unknown>;
	body: unknown;
	params: Record<string, unknown>;
	cookies?: Record<string, string>;
	ip?: string;
	ips?: string[];
	socket?: { remoteAddress?: string };
	protocol?: string;
	raw?: IncomingMessage;
	fastifyRequest?: FastifyRequest;
	on?: IncomingMessage['on'];
	once?: IncomingMessage['once'];
	pipe?: IncomingMessage['pipe'];
	unpipe?: IncomingMessage['unpipe'];
	pause?: IncomingMessage['pause'];
	resume?: IncomingMessage['resume'];
	read?: IncomingMessage['read'];
	file?: ApiUploadedFile;
	files?: ApiUploadedFile[] | Record<string, ApiUploadedFile[]>;
	apiReq?: ApiRequest;
}

export interface _ApiReply {
	locals: Record<string, unknown>;
	headersSent: boolean;
	status: (code: number) => _ApiReply;
	json: (payload: unknown) => void;
	send: (payload: unknown) => void;
	cookie: (name: string, value: string, options?: ApiCookieOptions) => void;
	clearCookie: (name: string, options?: ApiCookieOptions) => void;
}

export interface ApiTokenData extends JwtPayload, Partial<Token> {
	uid: unknown;
	iat?: number;
	exp?: number;
}

export type ApiAuthMethod = 'bearer' | 'cookie' | 'param' | 'apikey' | null;

export interface ApiRequest {
	server: ApiServer;
	req: ExtendedReq;
	res: _ApiReply;
	tokenData?: ApiTokenData | null;
	token?: string;
	authToken?: Token | null;
	apiKey?: ApiKey | null;
	authMethod?: ApiAuthMethod;
	clientInfo?: ClientInfo;
	realUid?: AuthIdentifier | null;
	getClientInfo: () => ClientInfo;
	getClientIp: () => string | null;
	getClientIpChain: () => string[];
	getRealUid: () => AuthIdentifier | null;
	isImpersonating: () => boolean;
}

export type ExpressApiRequest = ExtendedReq & {
	raw: IncomingMessage;
	fastifyRequest: FastifyRequest;
	on: IncomingMessage['on'];
	once: IncomingMessage['once'];
	pipe: IncomingMessage['pipe'];
	unpipe: IncomingMessage['unpipe'];
	pause: IncomingMessage['pause'];
	resume: IncomingMessage['resume'];
	read: IncomingMessage['read'];
};
export interface ExpressApiLocals {
	apiReq?: ApiRequest;
}

class FastifyResponseAdapter implements _ApiReply {
	public locals: Record<string, unknown> = {};
	private statusCode = 200;

	constructor(private readonly reply: FastifyReply) {}

	public get headersSent(): boolean {
		return this.reply.sent;
	}

	public status(code: number): _ApiReply {
		this.statusCode = code;
		this.reply.code(code);
		return this;
	}

	public json(payload: unknown): void {
		if (!this.reply.sent) {
			this.reply.code(this.statusCode).send(payload);
		}
	}

	public send(payload: unknown): void {
		if (!this.reply.sent) {
			this.reply.code(this.statusCode).send(payload);
		}
	}

	public cookie(name: string, value: string, options: ApiCookieOptions = {}): void {
		this.reply.setCookie(name, value, options as CookieSerializeOptions);
	}

	public clearCookie(name: string, options: ApiCookieOptions = {}): void {
		this.reply.clearCookie(name, options as CookieSerializeOptions);
	}
}

type NodeExcp = Error & {
	code?: string;
	errno?: number;
	syscall?: string;
	path?: string;
	address?: string;
};
type TokenStoreAdapter = {
	storeToken?: (data: Token) => Promise<void>;
	getToken?: (query: Partial<Token>, opts?: { includeExpired?: boolean }) => Promise<Token | null>;
	deleteToken?: (query: Partial<Token>) => Promise<number>;
	updateToken?: (updates: Partial<Token> & { refreshToken: string }) => Promise<boolean>;
	listTokens?: (
		userId: string | number,
		opts?: { limit?: number; offset?: number; includeExpired?: boolean }
	) => Promise<Token[]>;
};
type ModuleWithType = { moduleType?: string };
type CompatNext = (error?: unknown) => void;
type CompatRequestHandler = (req: ExpressApiRequest, res: _ApiReply, next: CompatNext) => unknown;
type CompatErrorHandler = (err: unknown, req: ExpressApiRequest, res: _ApiReply, next: CompatNext) => unknown;
interface ApiResponsePayload {
	errorId?: string;
	success: boolean;
	code: number;
	message: string;
	data: unknown;
	errors: Record<string, string>;
}
interface RefreshedAccessToken {
	token: string;
	tokenData: ApiTokenData;
	stored: Token;
}
interface AccessTokenState {
	token: string;
	tokenData: ApiTokenData;
}
interface InitialAccessToken {
	token: string;
	state: AccessTokenState | null;
}
interface VerifiedRefreshToken {
	token: string;
	tokenData: ApiTokenData;
}
interface SignedRefreshPair {
	accessToken: string;
	refreshToken: string;
	remainingSeconds: number;
}
interface FastifyValidationItem {
	params?: {
		missingProperty?: string;
		additionalProperty?: string;
	};
	instancePath?: string;
	message?: string;
}
type ApiCoreRouteConfig = FastifyContextConfig & {
	apiCoreParseMultipart?: boolean;
	apiCoreSigner?: RequestSigner | false;
};
type ResolvedRouteValidator = {
	adapter: ApiRouteValidatorAdapter;
	route: ApiRoute;
	contract: unknown;
};

class JwtHelperStore extends TokenStore {
	public async save(): Promise<void> {
		throw new Error('Token store is not configured');
	}
	public async get(): Promise<Token | null> {
		throw new Error('Token store is not configured');
	}
	public async delete(): Promise<number> {
		throw new Error('Token store is not configured');
	}
	public async update(): Promise<boolean> {
		throw new Error('Token store is not configured');
	}
	public async list(): Promise<Token[]> {
		return [];
	}
	public async close(): Promise<void> {
		return;
	}
}

const DEFAULT_DEBUG_SENSITIVE_KEYS = new Set([
	'password',
	'client_secret',
	'clientsecret',
	'secret',
	'accesstoken',
	'access_token',
	'refreshtoken',
	'refresh_token',
	'token',
	'apikey',
	'api_key',
	'authorization',
	'x-apicore-signature',
	'code_verifier',
	'codeverifier'
]);

function redactDebugValue(value: unknown, sensitiveKeys: ReadonlySet<string>): unknown {
	return redactSensitiveDebugValue(value, { sensitiveKeys, isRecord: isPlainObject });
}

export { ApiModule } from './api-module.js';
export type {
	ApiHandler,
	ApiHandlerRes,
	ApiHandlerResult,
	ApiAuthType,
	ApiAuthClass,
	ApiRoute,
	ApiRouteSchema,
	ApiRouteValidatorAdapter,
	ApiRouteValidatorContext,
	ApiKey
} from './api-module.js';

export interface ApiErrorParams {
	code?: number;
	message?: unknown;
	data?: unknown;
	errors?: Record<string, string>;
}

export class ApiError extends Error {
	public code: number;
	public data: unknown;
	public errors: Record<string, string>;

	constructor({ code, message, data, errors }: ApiErrorParams) {
		const msg = guessExceptionText(message, '[Unknown error (null/undefined)]');
		super(msg);
		this.message = msg;
		this.code = typeof code === 'number' ? code : 500;
		this.data = data !== undefined ? data : null;
		this.errors = errors !== undefined ? errors : {};
	}
}

export interface ApiErrorLoggedParams extends ApiErrorParams {
	cause: unknown;
}

export class ApiErrorLogged extends ApiError {
	public override readonly cause!: unknown;
	public readonly errorId = createErrorId();

	// Keep public error fields separate from server-side diagnostics.
	constructor({ cause, ...params }: ApiErrorLoggedParams) {
		super(params);
		Object.defineProperty(this, 'cause', { value: cause, enumerable: false });
	}
}

export interface ApiServerConf {
	rateLimits?: RateLimitConfig;
	securityEventSink?: SecurityEventSink;
	/** Application name used in /var/log/apicore-[appname].log. Defaults to app. */
	appName?: string;
	/** Error log path. Defaults to /var/log/apicore-[appname].log. */
	logFile?: string;
	apiPort: number;
	apiHost: string;
	/** Root directory for uploads. MIME and TUS files use `mime` and `tus` subdirectories. */
	uploadPath: string;
	uploadMax: number;
	uploadMinDiskFreeMB?: number;
	uploadMinDiskFreePercent?: number;
	/** Automatic orphan cleanup. `lazy` runs opportunistically without a timer. */
	uploadCleanup: UploadCleanupMode;
	/** Minimum time between automatic cleanup runs. Defaults to 15 minutes. */
	uploadCleanupIntervalSeconds: number;
	/** Incomplete or staged uploads older than this are orphaned. Defaults to 24 hours. */
	uploadOrphanExpirySeconds: number;
	staticDirs?: Record<string, string>;
	/**
	 * Cross-origin allowlist. Leave unset (or empty) to allow same-origin
	 * requests only — no `Access-Control-Allow-Origin` is emitted, so browsers
	 * block cross-origin reads. List explicit origins to permit them.
	 *
	 * To deliberately reflect every origin, set {@link ApiServerConf.corsAllowAll}.
	 */
	origins: string[];
	/**
	 * Reflect any request origin and allow credentials. This disables the
	 * browser's cross-origin protection for every site on the internet, so it
	 * must be opted into explicitly. `devMode` implies it when `origins` is
	 * empty. Ignored whenever `origins` is non-empty.
	 */
	corsAllowAll: boolean;
	debug: boolean;
	apiBasePath: string;
	swaggerEnabled?: boolean;
	swaggerPath?: string;
	accessSecret: string;
	refreshSecret: string;
	cookieDomain: string;
	cookiePath?: string;
	cookieSameSite?: 'lax' | 'strict' | 'none';
	cookieSecure?: boolean | 'auto';
	cookieHttpOnly?: boolean;
	apiKeyPrefix: string;
	apiKeyEnabled: boolean;
	/** Default signer required for requests unless a module or route overrides it. */
	signer?: RequestSigner;
	tokenParam: string;
	tokenParamLocation: 'body' | 'query' | 'body-query';
	accessCookie: string;
	refreshCookie: string;
	accessExpiry: number;
	refreshExpiry: number;
	sessionRefreshExpiry: number;
	authApi: boolean;
	devMode: boolean;
	hydrateGetBody: boolean;
	validateTokens: boolean;
	refreshMaybe: boolean;
	apiVersion: string;
	minClientVersion: string;
	tokenStore?: TokenStore;
	apiKeyStore?: ApiKeyStore;
	onStartError?: (error: Error) => void;
	/**
	 * Controls trust in proxy headers (X-Forwarded-For, Forwarded, X-Real-IP).
	 * - `false` (default): only use the socket address, ignore forwarded headers
	 * - `true`: trust all forwarded headers
	 * - number: trust that many rightmost forwarded entries (e.g., 1 = one reverse proxy)
	 */
	trustProxy: boolean | number;
	/**
	 * Enable multipart/form-data parsing for file uploads.
	 * Defaults to false. When enabled, files are staged under `uploadPath/mime`.
	 */
	multipartEnabled?: boolean;
}

type ApiServerConfigSection<Key extends keyof ApiServerConf> = Pick<ApiServerConf, Key>;

function positiveNumber(value: unknown): number | undefined {
	return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : undefined;
}

function fillUploadConfig(
	config: Partial<ApiServerConf>
): ApiServerConfigSection<
	| 'uploadPath'
	| 'uploadMax'
	| 'uploadMinDiskFreeMB'
	| 'uploadMinDiskFreePercent'
	| 'uploadCleanup'
	| 'uploadCleanupIntervalSeconds'
	| 'uploadOrphanExpirySeconds'
	| 'multipartEnabled'
> {
	return {
		uploadPath: config.uploadPath?.trim() || './uploads',
		uploadMax: config.uploadMax ?? 30 * 1024 * 1024,
		uploadMinDiskFreeMB: positiveNumber(config.uploadMinDiskFreeMB),
		uploadMinDiskFreePercent: positiveNumber(config.uploadMinDiskFreePercent),
		uploadCleanup:
			config.uploadCleanup === 'interval' || config.uploadCleanup === 'off' ? config.uploadCleanup : 'lazy',
		uploadCleanupIntervalSeconds: positiveNumber(config.uploadCleanupIntervalSeconds) ?? 15 * 60,
		uploadOrphanExpirySeconds: positiveNumber(config.uploadOrphanExpirySeconds) ?? 24 * 60 * 60,
		multipartEnabled: config.multipartEnabled ?? false
	};
}

function fillHttpConfig(
	config: Partial<ApiServerConf>
): ApiServerConfigSection<
	| 'appName'
	| 'logFile'
	| 'apiPort'
	| 'apiHost'
	| 'staticDirs'
	| 'origins'
	| 'corsAllowAll'
	| 'debug'
	| 'apiBasePath'
	| 'swaggerEnabled'
	| 'swaggerPath'
	| 'onStartError'
	| 'trustProxy'
> {
	return {
		appName: config.appName ?? 'app',
		logFile: config.logFile,
		apiPort: config.apiPort ?? 3101,
		apiHost: config.apiHost ?? 'localhost',
		staticDirs: config.staticDirs,
		origins: config.origins ?? [],
		// devMode implies allow-all so local tooling on arbitrary ports keeps working.
		corsAllowAll: config.corsAllowAll ?? config.devMode ?? false,
		debug: config.debug ?? false,
		apiBasePath: config.apiBasePath ?? '/api',
		swaggerEnabled: config.swaggerEnabled ?? false,
		swaggerPath: config.swaggerPath ?? '',
		onStartError: config.onStartError,
		trustProxy: config.trustProxy ?? false
	};
}

function fillCookieConfig(
	config: Partial<ApiServerConf>
): ApiServerConfigSection<'cookieDomain' | 'cookiePath' | 'cookieSameSite' | 'cookieSecure' | 'cookieHttpOnly'> {
	return {
		cookieDomain: config.cookieDomain ?? '',
		cookiePath: config.cookiePath ?? '/',
		cookieSameSite: config.cookieSameSite ?? 'lax',
		cookieSecure: config.cookieSecure ?? 'auto',
		cookieHttpOnly: config.cookieHttpOnly ?? true
	};
}

function fillTokenConfig(
	config: Partial<ApiServerConf>
): ApiServerConfigSection<
	| 'accessSecret'
	| 'refreshSecret'
	| 'accessCookie'
	| 'refreshCookie'
	| 'accessExpiry'
	| 'refreshExpiry'
	| 'sessionRefreshExpiry'
	| 'tokenStore'
> {
	return {
		accessSecret: config.accessSecret ?? '',
		refreshSecret: config.refreshSecret ?? '',
		accessCookie: config.accessCookie ?? 'dat',
		refreshCookie: config.refreshCookie ?? 'drt',
		accessExpiry: config.accessExpiry ?? 60 * 15,
		refreshExpiry: config.refreshExpiry ?? 30 * 24 * 60 * 60,
		sessionRefreshExpiry: config.sessionRefreshExpiry ?? 24 * 60 * 60,
		tokenStore: config.tokenStore
	};
}

function fillAuthConfig(
	config: Partial<ApiServerConf>
): ApiServerConfigSection<
	| 'apiKeyPrefix'
	| 'apiKeyEnabled'
	| 'signer'
	| 'tokenParam'
	| 'tokenParamLocation'
	| 'authApi'
	| 'devMode'
	| 'hydrateGetBody'
	| 'validateTokens'
	| 'refreshMaybe'
	| 'apiVersion'
	| 'minClientVersion'
	| 'apiKeyStore'
> {
	return {
		apiKeyPrefix: config.apiKeyPrefix ?? '',
		apiKeyEnabled: config.apiKeyEnabled ?? false,
		signer: config.signer,
		tokenParam: config.tokenParam ?? '',
		tokenParamLocation: config.tokenParamLocation ?? 'body',
		authApi: config.authApi ?? false,
		devMode: config.devMode ?? false,
		hydrateGetBody: config.hydrateGetBody ?? true,
		validateTokens: config.validateTokens ?? false,
		refreshMaybe: config.refreshMaybe ?? false,
		apiVersion: config.apiVersion ?? '',
		minClientVersion: config.minClientVersion ?? '',
		apiKeyStore: config.apiKeyStore
	};
}

function fillConfig(config: Partial<ApiServerConf>): ApiServerConf {
	return {
		...fillHttpConfig(config),
		...fillUploadConfig(config),
		...fillCookieConfig(config),
		...fillTokenConfig(config),
		...fillAuthConfig(config),
		rateLimits: config.rateLimits,
		securityEventSink: config.securityEventSink
	};
}

/** Core Fastify-based API server with module mounting and auth integration hooks. */
export class ApiServer {
	public readonly app: ((
		req: import('node:http').IncomingMessage,
		res: import('node:http').ServerResponse
	) => void) & {
		listen: (...args: unknown[]) => import('node:http').Server;
	};
	public readonly fastify: FastifyInstance;
	public readonly config: ApiServerConf;
	public readonly rateLimiter: RateLimitService;
	public readonly securityEvents: SecurityEventService;
	public readonly startedAt: number;
	private readonly apiBasePath: string;
	private finalized = false;
	private storageAdapter: AuthAdapter<unknown, unknown>;
	private moduleAdapter: AuthProviderModule<unknown>;
	private apiErrorHandlerInstalled = false;
	private tokenStoreAdapter: TokenStore | null = null;
	private apiKeyStoreAdapter: ApiKeyStore | null = null;
	private readonly jwtHelper: TokenStore;
	private compatGlobalErrorHandler: CompatErrorHandler | null = null;
	private readyPromise: Promise<void> | null = null;
	private readonly routeValidatorAdapters: ApiRouteValidatorAdapter[] = [];
	private readonly tusUploadStores = new Set<TusUploadStore>();
	private uploadCleanupTimer: ReturnType<typeof setInterval> | null = null;
	private uploadPurgePromise: Promise<UploadPurgeSummary> | null = null;
	private lastUploadCleanupAt = 0;
	private currReqDeprecationWarned = false;
	private readonly openApiDocument = new RuntimeOpenApiDocument();

	public get currReq(): ApiRequest | null {
		return null;
	}
	public set currReq(_value: ApiRequest | null) {
		if (this.config.devMode && !this.currReqDeprecationWarned) {
			this.currReqDeprecationWarned = true;
			console.warn(
				'[apicore] ApiServer.currReq is deprecated and always null. Use per-request ApiRequest in handlers.'
			);
		}
		void _value;
	}

	constructor(config: Partial<ApiServerConf> = {}) {
		this.config = fillConfig(config);
		this.rateLimiter = new RateLimitService(this.config.rateLimits);
		this.securityEvents = new SecurityEventService(this.config.securityEventSink);
		this.apiBasePath = this.normalizeApiBasePath(this.config.apiBasePath);
		this.startedAt = Date.now();
		this.storageAdapter = nullAuthAdapter;
		this.moduleAdapter = nullAuthModule;
		this.jwtHelper = new JwtHelperStore();
		this.tokenStoreAdapter = this.config.tokenStore ?? null;
		this.apiKeyStoreAdapter = this.config.apiKeyStore ?? null;
		this.fastify = fastify({
			logger: false,
			ajv: {
				customOptions: {
					allErrors: true,
					allowUnionTypes: true,
					removeAdditional: false
				}
			}
		});
		this.openApiDocument.registerPathPrefix('/api', this.apiBasePath);
		this.fastify.addHook('onRoute', (route) => {
			const signer = (route.config as ApiCoreRouteConfig | undefined)?.apiCoreSigner;
			this.openApiDocument.registerRoute(route.method, route.url, Boolean(signer));
		});
		this.setupRuntime();
		const appHandler = (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => {
			void this.prepareFastify()
				.then(() => {
					this.fastify.routing(req, res);
				})
				.catch((error: unknown) => {
					const payload = this.maskedErrorPayload(error);
					res.statusCode = 500;
					res.setHeader('content-type', 'application/json');
					res.end(JSON.stringify(payload));
				});
		};
		appHandler.listen = (...args: unknown[]) => {
			const server = this.fastify.server;
			void this.prepareFastify().then(() => {
				if (!server.listening) {
					(server.listen as (...listenArgs: unknown[]) => import('node:http').Server)(...args);
				}
			});
			return server;
		};
		this.app = appHandler;
	}

	private setupRuntime(): void {
		this.warnInsecureConfig();
		this.fastify.register(cookie);
		this.fastify.register(cors, {
			origin: (origin, callback) => {
				// No Origin header means a non-browser client (curl, server-to-server).
				// CORS is a browser security feature; non-browser clients can bypass it
				// by simply omitting the header, so blocking them here adds no security.
				if (!origin) {
					callback(null, true);
					return;
				}
				if (this.config.origins.length > 0) {
					if (!this.config.origins.includes(origin)) {
						callback(new Error('Not allowed by CORS'), false);
						return;
					}
					callback(null, true);
					return;
				}
				if (this.config.corsAllowAll) {
					callback(null, true);
					return;
				}
				// Default: same-origin only. Emitting no Access-Control-Allow-Origin
				// leaves the browser's same-origin policy in force. We deliberately do
				// not reject here — same-origin POST/PUT/DELETE also carry an Origin
				// header, and failing those would break the application itself.
				callback(null, false);
			},
			credentials: true,
			preflightContinue: true,
			strictPreflight: false
		});
		if (this.config.multipartEnabled) {
			this.fastify.register(multipart, {
				limits: { fileSize: this.config.uploadMax }
			});
		}

		this.fastify.addHook('preValidation', async (request) => {
			if (
				request.method === 'GET' &&
				request.body === undefined &&
				typeof request.headers['content-length'] === 'string' &&
				Number.parseInt(request.headers['content-length'], 10) > 0
			) {
				const rawBody = await this.readRawBody(request.raw);
				if (rawBody) {
					const contentType = (request.headers['content-type'] ?? '').toString().toLowerCase();
					(request as FastifyRequest & { body?: unknown }).body = this.parseRawBody(rawBody, contentType);
				}
			}
			const shouldParseMultipart = Boolean(
				(request.routeOptions.config as ApiCoreRouteConfig | undefined)?.apiCoreParseMultipart
			);
			if (!this.config.multipartEnabled || !shouldParseMultipart || !request.isMultipart()) {
				return;
			}
			const files: ApiUploadedFile[] = [];
			const body: Record<string, unknown> = {};
			for await (const part of request.parts()) {
				if (part.type === 'file') {
					files.push(await this.parseMultipartFile(part));
				} else {
					body[part.fieldname] = part.value;
				}
			}
			(request as FastifyRequest & { __apiParsedBody?: unknown }).__apiParsedBody = body;
			(
				request as FastifyRequest & {
					__apiParsedFiles?: ApiUploadedFile[];
				}
			).__apiParsedFiles = files;
		});
		this.fastify.addHook('preValidation', async (request) => {
			if (request.method === 'OPTIONS') return;
			const signer = (request.routeOptions.config as ApiCoreRouteConfig).apiCoreSigner;
			if (!signer) return;
			if (typeof request.isMultipart === 'function' && request.isMultipart()) {
				throw new ApiError({ code: 415, message: 'Signed multipart requests are not supported' });
			}
			try {
				await signer.verify({
					method: request.method,
					url: request.url,
					headers: request.headers,
					query: request.query,
					body: request.body
				});
			} catch (error) {
				if (error instanceof RequestSignatureError) {
					throw new ApiError({ code: 401, message: error.message });
				}
				throw error;
			}
		});

		this.installStaticDirs();
		this.installPingHandler();
		this.installUploadPurgeHandler();
		this.installSwaggerHandler();
		this.installApiNotFoundHandler();
		this.installApiErrorHandler();
		this.installUploadCleanupLifecycle();
	}

	/** Startup diagnostics for configurations that are unsafe in production. */
	private warnInsecureConfig(): void {
		const conf = this.config;
		if (conf.authApi && (!conf.accessSecret || !conf.refreshSecret)) {
			console.warn(
				'[apicore] Auth is enabled but accessSecret and/or refreshSecret are empty. JWT signing will fail at runtime.'
			);
		}
		if (conf.accessSecret && conf.accessSecret === conf.refreshSecret) {
			console.warn(
				'[apicore] accessSecret and refreshSecret are identical. Access and refresh tokens carry the ' +
					'same claims, so a shared secret makes each verifiable as the other. Use two distinct secrets.'
			);
		}
		if (conf.devMode) {
			return;
		}
		if (conf.corsAllowAll && conf.origins.length === 0) {
			console.warn(
				'[apicore] CORS: corsAllowAll is enabled — every browser origin may issue credentialed ' +
					'requests and read the responses. Set config.origins to an explicit allowlist in production.'
			);
		}
		const authConfigured = conf.authApi || Boolean(conf.accessSecret || conf.refreshSecret);
		if (authConfigured && conf.cookieSecure === 'auto' && conf.trustProxy === false) {
			console.warn(
				'[apicore] Auth cookies will omit the Secure attribute: cookieSecure is "auto" and trustProxy ' +
					'is false, so x-forwarded-proto is ignored and TLS terminated at a proxy is not detected. ' +
					'Set trustProxy to your proxy depth, or cookieSecure: true.'
			);
		}
	}

	private async readRawBody(req: import('node:http').IncomingMessage, maxBytes = 1_048_576): Promise<string> {
		const chunks: Buffer[] = [];
		let total = 0;
		for await (const chunk of req) {
			const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
			total += buf.length;
			if (total > maxBytes) {
				throw new ApiError({
					code: 413,
					message: `Request body exceeds maximum size of ${maxBytes} bytes`
				});
			}
			chunks.push(buf);
		}
		return Buffer.concat(chunks).toString('utf8');
	}

	private parseRawBody(raw: string, contentType: string): unknown {
		if (!raw) {
			return {};
		}
		if (contentType.includes('application/json')) {
			try {
				return JSON.parse(raw);
			} catch {
				return {};
			}
		}
		if (contentType.includes('application/x-www-form-urlencoded')) {
			const params = new URLSearchParams(raw);
			return Object.fromEntries(params.entries());
		}
		return raw;
	}

	private getMultipartUploadPath(): string | null {
		return this.config.multipartEnabled ? this.getUploadPath('mime') : null;
	}

	/** Resolve one of ApiCore's upload directories below the configured upload root. */
	public getUploadPath(kind: 'mime' | 'tus'): string {
		return path.resolve(this.config.uploadPath, kind);
	}

	/**
	 * Register a mounted TUS store for automatic and administrator-triggered
	 * orphan cleanup.
	 */
	public registerTusUploadStore(store: TusUploadStore): void {
		this.tusUploadStores.add(store);
	}

	/** Register a runtime path for operations described under a reference OpenAPI prefix. */
	public registerOpenApiPathPrefix(
		source: string,
		target: string,
		auth?: { type: ApiAuthType; req?: ApiAuthClass }
	): void {
		this.openApiDocument.registerPathPrefix(source, target, auth);
	}

	/**
	 * Prepare a disk-backed upload directory and enforce the configured free
	 * space floor. A low-space failure gets one cleanup attempt before the
	 * upload is rejected.
	 */
	public async prepareUploadDirectory(uploadPath: string, expectedBytes = 0): Promise<void> {
		await mkdir(uploadPath, { recursive: true, mode: 0o700 });
		this.requestLazyUploadCleanup();
		try {
			await this.assertUploadDiskHeadroom(uploadPath, expectedBytes);
		} catch (error) {
			if (!(error instanceof ApiError) || error.code !== 507) {
				throw error;
			}
			await this.purgeOrphanedUploads();
			await this.assertUploadDiskHeadroom(uploadPath, expectedBytes);
		}
	}

	private async assertUploadDiskHeadroom(uploadPath: string, expectedBytes = 0): Promise<void> {
		const minFreeMB = this.config.uploadMinDiskFreeMB;
		const minFreePercent = this.config.uploadMinDiskFreePercent;
		if (minFreeMB === undefined && minFreePercent === undefined) {
			return;
		}
		const stats = await statfs(uploadPath);
		const rawBlockSize = (stats as { frsize?: number | bigint }).frsize ?? stats.bsize;
		const blockSize = Number(rawBlockSize);
		const freeBytes = Math.max(0, Number(stats.bavail) * blockSize - Math.max(0, expectedBytes));
		const totalBytes = Number(stats.blocks) * blockSize;
		const freeMB = freeBytes / (1024 * 1024);
		const freePercent = totalBytes > 0 ? (freeBytes / totalBytes) * 100 : 0;

		if (minFreeMB !== undefined && freeMB < minFreeMB) {
			throw new ApiError({
				code: 507,
				message: `Upload denied: free disk space ${freeMB.toFixed(1)} MB is below configured minimum of ${minFreeMB} MB`
			});
		}
		if (minFreePercent !== undefined && freePercent < minFreePercent) {
			throw new ApiError({
				code: 507,
				message: `Upload denied: free disk space ${freePercent.toFixed(1)}% is below configured minimum of ${minFreePercent}%`
			});
		}
	}

	/** Remove expired MIME staging files and incomplete TUS uploads. */
	public async purgeOrphanedUploads(): Promise<UploadPurgeSummary> {
		if (this.uploadPurgePromise) {
			return this.uploadPurgePromise;
		}
		const cutoff = new Date(Date.now() - this.config.uploadOrphanExpirySeconds * 1000);
		this.lastUploadCleanupAt = Date.now();
		this.uploadPurgePromise = this.performUploadPurge(cutoff).finally(() => {
			this.uploadPurgePromise = null;
		});
		return this.uploadPurgePromise;
	}

	private async performUploadPurge(cutoff: Date): Promise<UploadPurgeSummary> {
		const mime = await this.purgeMimeUploads(cutoff);
		const tus: UploadPurgeResult = { uploads: 0, bytes: 0 };
		for (const store of this.tusUploadStores) {
			if (!store.purgeExpired) {
				continue;
			}
			const removed = await store.purgeExpired(cutoff);
			tus.uploads += removed.uploads;
			tus.bytes += removed.bytes;
		}
		return {
			cutoff: cutoff.toISOString(),
			mime,
			tus,
			total: {
				uploads: mime.uploads + tus.uploads,
				bytes: mime.bytes + tus.bytes
			}
		};
	}

	private async purgeMimeUploads(cutoff: Date): Promise<UploadPurgeResult> {
		const uploadPath = this.getUploadPath('mime');
		let entries;
		try {
			entries = await readdir(uploadPath, { withFileTypes: true });
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
				return { uploads: 0, bytes: 0 };
			}
			throw error;
		}
		const result: UploadPurgeResult = { uploads: 0, bytes: 0 };
		for (const entry of entries) {
			if (!entry.isFile() && !entry.isSymbolicLink()) {
				continue;
			}
			const filepath = path.join(uploadPath, entry.name);
			const removedBytes = await removeStaleUploadFile(filepath, cutoff);
			if (removedBytes !== null) {
				result.uploads += 1;
				result.bytes += removedBytes;
			}
		}
		return result;
	}

	private requestLazyUploadCleanup(): void {
		if (this.config.uploadCleanup !== 'lazy') {
			return;
		}
		const intervalMs = this.config.uploadCleanupIntervalSeconds * 1000;
		if (Date.now() - this.lastUploadCleanupAt < intervalMs || this.uploadPurgePromise) {
			return;
		}
		void this.purgeOrphanedUploads().catch((error: unknown) => {
			this.logUnhandledError('Automatic upload cleanup failed', error);
		});
	}

	private installUploadCleanupLifecycle(): void {
		if (this.config.uploadCleanup !== 'interval') {
			return;
		}
		this.fastify.addHook('onReady', async () => {
			if (this.uploadCleanupTimer) {
				return;
			}
			this.uploadCleanupTimer = setInterval(() => {
				void this.purgeOrphanedUploads().catch((error: unknown) => {
					this.logUnhandledError('Scheduled upload cleanup failed', error);
				});
			}, this.config.uploadCleanupIntervalSeconds * 1000);
			this.uploadCleanupTimer.unref();
		});
		this.fastify.addHook('onClose', async () => {
			if (this.uploadCleanupTimer) {
				clearInterval(this.uploadCleanupTimer);
				this.uploadCleanupTimer = null;
			}
		});
	}

	private isMultipartLimitError(error: unknown): boolean {
		const message = error instanceof Error ? error.message : String(error ?? '');
		return /file too large|request file too large|limit reached|max file size/i.test(message);
	}

	private multipartTooLargeError(): ApiError {
		return new ApiError({
			code: 413,
			message: `Upload exceeds maximum size of ${this.config.uploadMax} bytes`
		});
	}

	private throwMultipartError(error: unknown): never {
		if (error instanceof ApiError) {
			throw error;
		}
		if (this.isMultipartLimitError(error)) {
			throw this.multipartTooLargeError();
		}
		throw error;
	}

	private createMultipartByteCounter(
		stagedUploadPath: string,
		progress: { size: number; sinceLastDiskCheck: number }
	): Transform {
		const diskCheckInterval = 4 * 1024 * 1024;
		return new Transform({
			transform: (chunk, _encoding, callback) => {
				const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array | string);
				progress.size += buffer.length;
				progress.sinceLastDiskCheck += buffer.length;
				if (progress.size > this.config.uploadMax) {
					callback(this.multipartTooLargeError());
					return;
				}
				if (progress.sinceLastDiskCheck < diskCheckInterval) {
					callback(null, buffer);
					return;
				}
				progress.sinceLastDiskCheck = 0;
				void this.prepareUploadDirectory(stagedUploadPath, buffer.length)
					.then(() => callback(null, buffer))
					.catch((error: unknown) => callback(error as Error));
			}
		});
	}

	private async readMultipartFileToMemory(part: MultipartFile, originalname: string): Promise<ApiUploadedFile> {
		try {
			const buffer = await part.toBuffer();
			return {
				fieldname: part.fieldname,
				originalname,
				encoding: part.encoding,
				mimetype: part.mimetype,
				size: buffer.length,
				buffer
			};
		} catch (error) {
			this.throwMultipartError(error);
		}
	}

	private async stageMultipartFile(
		part: MultipartFile,
		originalname: string,
		stagedUploadPath: string
	): Promise<ApiUploadedFile> {
		await this.prepareUploadDirectory(stagedUploadPath);
		const safeName = path.basename(originalname || 'upload.bin');
		const filepath = path.join(stagedUploadPath, `${Date.now()}-${randomUUID()}-${safeName}`);
		const progress = { size: 0, sinceLastDiskCheck: 0 };
		const countBytes = this.createMultipartByteCounter(stagedUploadPath, progress);
		try {
			await pipeline(part.file, countBytes, createWriteStream(filepath, { flags: 'wx', mode: 0o600 }));
			if (part.file.truncated) {
				throw this.multipartTooLargeError();
			}
			return {
				fieldname: part.fieldname,
				originalname,
				encoding: part.encoding,
				mimetype: part.mimetype,
				size: progress.size,
				filepath
			};
		} catch (error) {
			await rm(filepath, { force: true }).catch(() => undefined);
			this.throwMultipartError(error);
		}
	}

	private async parseMultipartFile(part: MultipartFile): Promise<ApiUploadedFile> {
		const originalname = part.filename ?? '';
		const stagedUploadPath = this.getMultipartUploadPath();
		return stagedUploadPath
			? this.stageMultipartFile(part, originalname, stagedUploadPath)
			: this.readMultipartFileToMemory(part, originalname);
	}

	private assertNotFinalized(action: string): void {
		if (this.finalized) {
			throw new Error(`Cannot call ApiServer.${action}() after finalize()/start()`);
		}
	}

	private prepareFastify(): Promise<void> {
		this.finalized = true;
		if (!this.readyPromise) {
			this.readyPromise = Promise.resolve(this.fastify.ready()).then(() => undefined);
		}
		return this.readyPromise;
	}

	public finalize(): this {
		void this.prepareFastify();
		return this;
	}

	public authStorage<UserRow, SafeUser>(storage: AuthAdapter<UserRow, SafeUser>): this {
		this.assertNotFinalized('authStorage');
		this.storageAdapter = storage as AuthAdapter<unknown, unknown>;
		return this;
	}

	public useAuthStorage<UserRow, SafeUser>(storage: AuthAdapter<UserRow, SafeUser>): this {
		return this.authStorage(storage);
	}

	public authModule<UserRow>(module: AuthProviderModule<UserRow>): this {
		this.assertNotFinalized('authModule');
		this.moduleAdapter = module as AuthProviderModule<unknown>;
		return this;
	}

	public useAuthModule<UserRow>(module: AuthProviderModule<UserRow>): this {
		return this.authModule(module);
	}

	public getAuthStorage<UserRow = unknown, SafeUser = unknown>(): AuthAdapter<UserRow, SafeUser> {
		return this.storageAdapter as AuthAdapter<UserRow, SafeUser>;
	}

	public getAuthModule<UserRow = unknown>(): AuthProviderModule<UserRow> {
		return this.moduleAdapter as AuthProviderModule<UserRow>;
	}

	public setTokenStore(store: TokenStore): this {
		this.assertNotFinalized('setTokenStore');
		this.tokenStoreAdapter = store;
		return this;
	}

	public getTokenStore(): TokenStore | null {
		return this.tokenStoreAdapter;
	}

	public setApiKeyStore(store: ApiKeyStore): this {
		this.assertNotFinalized('setApiKeyStore');
		this.apiKeyStoreAdapter = store;
		return this;
	}

	public getApiKeyStore(): ApiKeyStore | null {
		return this.apiKeyStoreAdapter;
	}

	public addValidatorAdapter(adapter: ApiRouteValidatorAdapter): this {
		this.assertNotFinalized('addValidatorAdapter');
		const name = typeof adapter.name === 'string' ? adapter.name.trim() : '';
		if (!name) {
			throw new Error('ApiServer.addValidatorAdapter() requires adapter.name');
		}
		if (typeof adapter.supports !== 'function') {
			throw new Error(`ApiServer.addValidatorAdapter(${name}) requires adapter.supports`);
		}
		if (typeof adapter.validate !== 'function') {
			throw new Error(`ApiServer.addValidatorAdapter(${name}) requires adapter.validate`);
		}
		if (this.routeValidatorAdapters.some((candidate) => candidate.name === name)) {
			throw new Error(`ApiServer.addValidatorAdapter() received duplicate adapter name: ${name}`);
		}
		this.routeValidatorAdapters.push(adapter);
		return this;
	}

	public async listUserCredentials(userId: AuthIdentifier): Promise<StoredPasskeyCredential[]> {
		if (typeof this.storageAdapter.listUserCredentials !== 'function') {
			throw new Error('Passkey service is not configured');
		}
		return this.storageAdapter.listUserCredentials(userId);
	}

	public async deletePasskeyCredential(credentialId: Buffer | string): Promise<boolean> {
		if (typeof this.storageAdapter.deletePasskeyCredential !== 'function') {
			throw new Error('Passkey service is not configured');
		}
		return this.storageAdapter.deletePasskeyCredential(credentialId);
	}

	public async getUser(identifier: AuthIdentifier): Promise<unknown | null> {
		return this.storageAdapter.getUser(identifier);
	}

	public getUserPasswordHash(user: unknown): string {
		return this.storageAdapter.getUserPasswordHash(user);
	}

	public getUserId(user: unknown): AuthIdentifier {
		return this.storageAdapter.getUserId(user);
	}

	public filterUser(user: unknown): unknown {
		return this.storageAdapter.filterUser(user);
	}

	public async verifyPassword(password: string, hash: string): Promise<boolean> {
		return this.storageAdapter.verifyPassword(password, hash);
	}

	public async storeToken(data: Token): Promise<void> {
		if (this.tokenStoreAdapter) {
			return this.tokenStoreAdapter.save(data);
		}
		const storage = this.storageAdapter as TokenStoreAdapter;
		if (typeof storage.storeToken === 'function') {
			return storage.storeToken(data);
		}
		throw new Error('Token store is not configured');
	}

	public async getToken(query: TokenIdentityQuery, opts?: { includeExpired?: boolean }): Promise<Token | null> {
		const normalized = normalizeTokenIdentityQuery(query);
		if (this.tokenStoreAdapter) {
			return this.tokenStoreAdapter.get(normalized, opts);
		}
		const storage = this.storageAdapter as TokenStoreAdapter;
		if (typeof storage.getToken === 'function') {
			return storage.getToken(normalized, opts);
		}
		return null;
	}

	public async deleteToken(query: TokenIdentityQuery): Promise<number> {
		const normalized = normalizeTokenIdentityQuery(query);
		if (this.tokenStoreAdapter) {
			return this.tokenStoreAdapter.delete(normalized);
		}
		const storage = this.storageAdapter as TokenStoreAdapter;
		if (typeof storage.deleteToken === 'function') {
			return storage.deleteToken(normalized);
		}
		return 0;
	}

	public async listTokens(
		userId: AuthIdentifier,
		opts?: { limit?: number; offset?: number; includeExpired?: boolean }
	): Promise<Token[]> {
		const normalizedUserId = String(userId);
		if (this.tokenStoreAdapter) {
			return this.tokenStoreAdapter.list(normalizedUserId, opts);
		}
		const storage = this.storageAdapter as TokenStoreAdapter;
		if (typeof storage.listTokens === 'function') {
			return storage.listTokens(normalizedUserId, opts);
		}
		return [];
	}

	public async createPasskeyChallenge(params: PasskeyChallengeParams): Promise<PasskeyChallenge> {
		if (typeof this.storageAdapter.createPasskeyChallenge !== 'function') {
			throw new Error('Passkey service is not configured');
		}
		return this.storageAdapter.createPasskeyChallenge(params);
	}

	public async verifyPasskeyResponse(params: PasskeyVerificationParams): Promise<PasskeyVerificationResult> {
		if (typeof this.storageAdapter.verifyPasskeyResponse !== 'function') {
			throw new Error('Passkey service is not configured');
		}
		return this.storageAdapter.verifyPasskeyResponse(params);
	}

	public async getClient(clientId: string): Promise<OAuthClient | null> {
		if (typeof this.storageAdapter.getClient !== 'function') {
			return null;
		}
		return this.storageAdapter.getClient(clientId);
	}

	public async verifyClientSecret(client: OAuthClient, clientSecret: string | null): Promise<boolean> {
		if (typeof this.storageAdapter.verifyClientSecret !== 'function') {
			throw new Error('OAuth store is not configured');
		}
		return this.storageAdapter.verifyClientSecret(client, clientSecret);
	}

	public async createAuthCode(request: AuthCodeRequest): Promise<AuthCodeData> {
		if (typeof this.storageAdapter.createAuthCode !== 'function') {
			throw new Error('OAuth store is not configured');
		}
		return this.storageAdapter.createAuthCode(request);
	}

	public async consumeAuthCode(code: string, clientId: string): Promise<AuthCodeData | null> {
		if (typeof this.storageAdapter.consumeAuthCode !== 'function') {
			return null;
		}
		const consumed = await this.storageAdapter.consumeAuthCode(code, clientId);
		if (!consumed || consumed.clientId !== clientId) {
			return null;
		}
		return consumed;
	}

	public async canImpersonate(params: {
		realUserId: AuthIdentifier;
		effectiveUserId: AuthIdentifier;
	}): Promise<boolean> {
		if (typeof this.storageAdapter.canImpersonate === 'function') {
			return !!(await this.storageAdapter.canImpersonate(params));
		}
		return params.realUserId === params.effectiveUserId;
	}

	public jwtSign(
		payload: JwtSignPayload,
		secret: string,
		expiresInSeconds: number,
		options?: SignOptions
	): JwtSignResult {
		if (!secret) {
			return { success: false, error: 'JWT secret is not configured' };
		}
		return (this.tokenStoreAdapter ?? this.jwtHelper).jwtSign(payload, secret, expiresInSeconds, options);
	}

	public jwtVerify<T>(token: string, secret: string, options?: VerifyOptions): JwtVerifyResult<T> {
		return (this.tokenStoreAdapter ?? this.jwtHelper).jwtVerify<T>(token, secret, options);
	}

	public jwtDecode<T>(token: string, options?: import('jsonwebtoken').DecodeOptions): JwtDecodeResult<T> {
		return (this.tokenStoreAdapter ?? this.jwtHelper).jwtDecode<T>(token, options);
	}

	public async getApiKey<T = ApiKey>(token: string): Promise<T | null> {
		if (this.apiKeyStoreAdapter) {
			return (await this.apiKeyStoreAdapter.get(token)) as T | null;
		}
		console.warn(
			'[apicore] getApiKey() is not implemented. ' +
				'Override getApiKey() or configure setApiKeyStore() to support API key authentication.'
		);
		return null;
	}

	public async authenticateUser(params: { login: string; password: string }): Promise<boolean> {
		if (!params?.login || !params?.password) {
			return false;
		}
		const user = await this.storageAdapter.getUser(params.login);
		if (!user) {
			return false;
		}
		const hash = this.storageAdapter.getUserPasswordHash(user);
		return this.storageAdapter.verifyPassword(params.password, hash);
	}

	public async updateToken(updates: Partial<Token> & { refreshToken: string }): Promise<boolean> {
		if (this.tokenStoreAdapter) {
			return this.tokenStoreAdapter.update(updates);
		}
		const storage = this.storageAdapter as TokenStoreAdapter;
		if (typeof storage.updateToken === 'function') {
			return storage.updateToken(updates);
		}
		return false;
	}
	public guessExceptionText(error: unknown, defMsg: string = 'Unknown Error') {
		return guessExceptionText(error, defMsg);
	}

	protected async authorize(apiReq: ApiRequest, requiredClass: ApiAuthClass): Promise<void> {
		if (requiredClass === 'admin' && apiReq.tokenData?.role !== 'admin') {
			throw new ApiError({ code: 403, message: 'Forbidden' });
		}
	}

	/**
	 * Authenticate and authorise an incoming Fastify request outside of the
	 * standard `defineRoutes` pipeline (e.g. TUS upload routes that need full
	 * control over their own response format).
	 *
	 * Throws `ApiError` on auth failure — callers should catch it and respond
	 * with the appropriate HTTP status code.
	 */
	public async resolveRequest(
		request: FastifyRequest,
		reply: FastifyReply,
		auth: { type: ApiAuthType; req?: ApiAuthClass }
	): Promise<ApiRequest> {
		const req = this.toExtendedReq(request);
		const res = new FastifyResponseAdapter(reply);
		const apiReq = this.createApiRequest(req, res);
		apiReq.tokenData = await this.authenticate(apiReq, auth.type);
		await this.authorize(apiReq, auth.req ?? 'any');
		return apiReq;
	}

	public async authenticateRequest(apiReq: ApiRequest, authType: ApiAuthType): Promise<ApiTokenData | null> {
		apiReq.tokenData = await this.authenticate(apiReq, authType);
		return apiReq.tokenData;
	}

	private installStaticDirs(): void {
		const staticDirs = this.config.staticDirs;
		if (!staticDirs || !isPlainObject(staticDirs)) {
			return;
		}
		for (const [mountRaw, dirRaw] of Object.entries(staticDirs)) {
			const mount = typeof mountRaw === 'string' ? mountRaw.trim() : '';
			const dir = typeof dirRaw === 'string' ? dirRaw.trim() : '';
			if (!mount || !dir) {
				continue;
			}
			const resolvedMount = mount.startsWith('/') ? mount : `/${mount}`;
			void this.fastify.register(fastifyStatic, {
				root: dir,
				prefix: resolvedMount.endsWith('/') ? resolvedMount : `${resolvedMount}/`,
				decorateReply: false
			});
		}
	}

	private installPingHandler(): void {
		this.fastify.get(`${this.apiBasePath}/v1/ping`, { schema: { querystring: emptyObjectSchema } }, async () => {
			const payload = {
				success: true,
				status: 'ok',
				apiVersion: this.config.apiVersion ?? '',
				minClientVersion: this.config.minClientVersion ?? '',
				uptimeSec: process.uptime(),
				startedAt: this.startedAt,
				timestamp: new Date().toISOString()
			};
			return {
				success: true,
				code: 200,
				message: 'Success',
				data: payload,
				errors: {}
			};
		});
	}

	private installUploadPurgeHandler(): void {
		this.fastify.post(
			`${this.apiBasePath}/v1/uploads/purge`,
			{
				schema: {
					querystring: emptyObjectSchema
				}
			},
			async (request, reply) => {
				await this.resolveRequest(request, reply, { type: 'strict', req: 'admin' });
				const result = await this.purgeOrphanedUploads();
				return {
					success: true,
					code: 200,
					message: 'Success',
					data: result,
					errors: {}
				};
			}
		);
	}

	private async loadSwaggerSpec(): Promise<Record<string, unknown> | null> {
		const candidates = [path.resolve(process.cwd(), 'docs/swagger/openapi.json')];
		if (typeof __dirname === 'string') {
			candidates.push(path.resolve(__dirname, '../../docs/swagger/openapi.json'));
		}
		let packageRoot: string | undefined;
		try {
			const require = createRequire(path.join(process.cwd(), 'package.json'));
			const entry = require.resolve('@technomoron/apicore-server');
			packageRoot = path.resolve(path.dirname(entry), '..', '..');
			candidates.push(path.join(packageRoot, 'docs/swagger/openapi.json'));
		} catch {
			// Ignore resolution failures; fall back to any existing candidate.
		}

		for (const candidate of candidates) {
			try {
				await access(candidate);
			} catch {
				continue;
			}
			try {
				const raw = await readFile(candidate, 'utf8');
				const spec = JSON.parse(raw) as Record<string, unknown>;
				// Inject version from package.json at runtime
				const version = await this.readPackageVersion(path.dirname(candidate));
				if (version && spec.info && typeof spec.info === 'object') {
					(spec.info as Record<string, unknown>).version = version;
				}
				return this.openApiDocument.build(spec);
			} catch {
				return null;
			}
		}
		return null;
	}

	private async readPackageVersion(specDir: string): Promise<string | null> {
		// Walk up from the spec directory looking for package.json
		const candidates = [
			path.resolve(specDir, '../../package.json'),
			path.resolve(specDir, '../package.json'),
			path.resolve(process.cwd(), 'package.json')
		];
		for (const candidate of candidates) {
			try {
				const raw = await readFile(candidate, 'utf8');
				const pkg = JSON.parse(raw) as { version?: string };
				if (typeof pkg.version === 'string') {
					return pkg.version;
				}
			} catch {
				continue;
			}
		}
		return null;
	}

	private installSwaggerHandler(): void {
		const rawPath = typeof this.config.swaggerPath === 'string' ? this.config.swaggerPath.trim() : '';
		const enabled = Boolean(this.config.swaggerEnabled) || rawPath.length > 0;
		if (!enabled) {
			return;
		}
		const base = this.apiBasePath === '/' ? '' : this.apiBasePath;
		const resolved = rawPath.length > 0 ? rawPath : `${base}/swagger`;
		const routePath = resolved.startsWith('/') ? resolved : `/${resolved}`;
		let specPromise: Promise<Record<string, unknown> | null> | undefined;
		this.fastify.get(routePath, { schema: { querystring: emptyObjectSchema } }, async (_request, reply) => {
			if (!specPromise) {
				specPromise = this.loadSwaggerSpec();
			}
			const spec = await specPromise;
			if (!spec) {
				// Clear cached failure so next request retries
				specPromise = undefined;
			}
			if (!spec) {
				reply.code(500);
				return {
					success: false,
					code: 500,
					message: 'Swagger spec is unavailable',
					data: null,
					errors: {}
				};
			}
			return spec;
		});
	}

	private normalizeApiBasePath(routePath?: string): string {
		if (!routePath || typeof routePath !== 'string') {
			return '/api';
		}
		const trimmed = routePath.trim();
		if (!trimmed) {
			return '/api';
		}
		const withLeadingSlash = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
		if (withLeadingSlash.length === 1) {
			return withLeadingSlash;
		}
		return withLeadingSlash.replace(/\/+$/, '') || '/api';
	}

	private installApiNotFoundHandler(): void {
		this.fastify.setNotFoundHandler((request, reply) => {
			const target = request.raw.url ?? request.url;
			if (!target.startsWith(this.apiBasePath)) {
				reply.code(404).send('Not Found');
				return;
			}
			const method = request.method.toUpperCase();
			reply.code(404).send({
				success: false,
				code: 404,
				message: `No such endpoint: ${method} ${target}`,
				data: null,
				errors: {}
			});
		});
	}

	private installApiErrorHandler(): void {
		if (this.apiErrorHandlerInstalled) {
			return;
		}
		this.apiErrorHandlerInstalled = true;
		this.fastify.setErrorHandler((error, request, reply) => this.handleFastifyError(error, request, reply));
	}

	private failurePayload(code: number, message: string, errors: Record<string, string> = {}): ApiResponsePayload {
		return {
			success: false,
			code,
			message,
			data: null,
			errors
		};
	}

	private validationFieldErrors(error: unknown): Record<string, string> | null {
		const validation = (error as { validation?: FastifyValidationItem[] }).validation;
		if (!Array.isArray(validation)) {
			return null;
		}
		const fieldErrors: Record<string, string> = {};
		for (const item of validation) {
			const field =
				item.params?.missingProperty ??
				item.params?.additionalProperty ??
				(item.instancePath?.replace(/^\//, '') || 'body');
			fieldErrors[field] = item.message ?? 'Invalid value';
		}
		return fieldErrors;
	}

	private sendCorsError(request: FastifyRequest, reply: FastifyReply): void {
		const target = request.raw.url ?? request.url;
		if (target.startsWith(this.apiBasePath)) {
			reply.code(403).send(this.failurePayload(403, 'Origin not allowed by CORS'));
			return;
		}
		reply.code(403).send('Origin not allowed by CORS');
	}

	// Send known request errors or mask server failures.
	private sendFastifyStatusError(error: unknown, status: number, reply: FastifyReply): void {
		if (status >= 500) {
			reply.code(500).send(this.maskedErrorPayload(error));
			return;
		}
		const message =
			status === 413
				? `Upload exceeds maximum size of ${this.config.uploadMax} bytes`
				: status === 400
					? 'Invalid request payload'
					: 'Internal server error';
		reply.code(status).send(this.failurePayload(status, message));
	}

	// Format public errors and mask unexpected Fastify failures.
	private handleFastifyError(error: unknown, request: FastifyRequest, reply: FastifyReply): void {
		const message = error instanceof Error ? error.message : '';
		if (message.includes('Not allowed by CORS')) {
			this.sendCorsError(request, reply);
			return;
		}
		const fieldErrors = this.validationFieldErrors(error);
		if (fieldErrors) {
			reply.code(400).send(this.failurePayload(400, 'Validation failed', fieldErrors));
			return;
		}
		if (error instanceof ApiError || isApiErrorLike(error)) {
			const apiError = error as ApiErrorLike;
			reply.code(apiError.code).send(this.apiErrorPayload(apiError));
			return;
		}
		const status = asHttpStatus(error);
		if (status) {
			this.sendFastifyStatusError(error, status, reply);
			return;
		}
		reply.code(500).send(this.maskedErrorPayload(error));
	}

	// Preserve public error fields and log private causes.
	private apiErrorPayload(apiError: ApiErrorLike): ApiResponsePayload {
		const logged = apiError instanceof ApiErrorLogged;
		if (logged) {
			this.logUnhandledError('ApiErrorLogged', apiError.cause, apiError.errorId);
		}
		return {
			...(logged ? { errorId: apiError.errorId } : {}),
			success: false,
			code: apiError.code,
			message: apiError.message,
			data: apiError.data ?? null,
			errors:
				apiError.errors && typeof apiError.errors === 'object' && !Array.isArray(apiError.errors)
					? (apiError.errors as Record<string, string>)
					: {}
		};
	}

	public start(): this {
		if (!this.finalized) {
			console.warn(
				'[apicore] ApiServer.start() called without finalize(); auto-finalizing. Call server.finalize() before start() to silence this warning.'
			);
			this.finalize();
		}
		void this.fastify
			.listen({
				port: this.config.apiPort,
				host: this.config.apiHost
			})
			.then(() => {
				console.log(`Server is running on http://${this.config.apiHost}:${this.config.apiPort}`);
			})
			.catch((error: NodeExcp) => {
				let message: string;
				if (error.code === 'EADDRINUSE') {
					message = `Port ${this.config.apiPort} is already in use.`;
				} else if (error.code === 'EACCES') {
					message = `Insufficient permissions to bind to port ${this.config.apiPort}. Try using a port number >= 1024 or running with elevated privileges.`;
				} else if (error.code === 'EADDRNOTAVAIL') {
					message = `Address ${this.config.apiHost} is not available on this machine.`;
				} else {
					message = `Failed to start server: ${error.message}`;
				}

				const err = new Error(message);
				(err as unknown as { cause?: unknown }).cause = error;
				if (typeof this.config.onStartError === 'function') {
					this.config.onStartError(err);
					return;
				}
				this.logUnhandledError('Server startup failed', err);
				process.exitCode = 1;
			});
		return this;
	}

	// Correlate masked responses with server-side diagnostics.
	private maskedErrorPayload(error: unknown): ApiResponsePayload {
		const errorId = createErrorId();
		this.logUnhandledError('Unexpected error', error, errorId);
		return { ...this.failurePayload(500, 'Internal server error'), errorId };
	}

	// Write redacted diagnostics using the application's log file.
	private logUnhandledError(context: string, error: unknown, errorId = createErrorId()): void {
		logError(
			this.config.appName ?? 'app',
			errorId,
			context,
			error,
			[this.config.accessSecret, this.config.refreshSecret],
			this.config.logFile
		);
	}

	private async verifyJWT(token: string): Promise<{
		tokenData: ApiTokenData | undefined;
		error: string | undefined;
		expired?: boolean;
	}> {
		if (!this.config.accessSecret) {
			return {
				tokenData: undefined,
				error: 'JWT authentication disabled; no jwtSecret set',
				expired: false
			};
		}

		const result = this.jwtVerify<ApiTokenData>(token, this.config.accessSecret);

		if (!result.success) {
			return {
				tokenData: undefined,
				error: result.error,
				expired: result.expired
			};
		}

		if (result.data!.uid == null) {
			return {
				tokenData: undefined,
				error: 'Missing/bad userid in token',
				expired: false
			};
		}

		return { tokenData: result.data, error: undefined, expired: false };
	}

	private jwtCookieOptions(apiReq: ApiRequest): ApiCookieOptions {
		return buildAuthCookieOptions(this.config, apiReq.req);
	}

	private setAccessCookie(apiReq: ApiRequest, accessToken: string, sessionCookie: boolean): void {
		const conf = this.config;
		const options = this.jwtCookieOptions(apiReq);
		const accessMaxAge = Math.max(1, conf.accessExpiry) * 1000;
		const accessOptions = sessionCookie ? options : { ...options, maxAge: accessMaxAge };
		apiReq.res.cookie(conf.accessCookie, accessToken, accessOptions);
	}

	private setRefreshCookie(
		apiReq: ApiRequest,
		refreshToken: string,
		sessionCookie: boolean,
		ttlSeconds: number
	): void {
		const conf = this.config;
		const options = this.jwtCookieOptions(apiReq);
		const refreshMaxAge = Math.max(1, ttlSeconds) * 1000;
		const refreshOptions = sessionCookie ? options : { ...options, maxAge: refreshMaxAge };
		apiReq.res.cookie(conf.refreshCookie, refreshToken, refreshOptions);
	}

	private readVerifiedRefreshToken(apiReq: ApiRequest): VerifiedRefreshToken | null {
		const conf = this.config;
		if (!conf.refreshSecret || !conf.accessSecret) {
			return null;
		}
		const rawRefresh = apiReq.req.cookies?.[conf.refreshCookie];
		if (typeof rawRefresh !== 'string') {
			return null;
		}
		const refreshToken = rawRefresh.trim();
		if (!refreshToken) {
			return null;
		}

		const verify = this.jwtVerify<ApiTokenData>(refreshToken, conf.refreshSecret);
		if (!verify.success || !verify.data) {
			return null;
		}
		return { token: refreshToken, tokenData: verify.data };
	}

	private async loadBoundRefreshToken(verified: VerifiedRefreshToken): Promise<Token | null> {
		let stored: Token | null;
		try {
			stored = await this.getToken({ refreshToken: verified.token });
		} catch {
			return null;
		}
		if (!stored) {
			return null;
		}
		const storedUid = String(stored.userId);
		const verifyUid = verified.tokenData.uid != null ? String(verified.tokenData.uid) : null;
		// A missing uid claim is treated as a binding failure, not a skip.
		if (!verifyUid || verifyUid !== storedUid) {
			return null;
		}
		return stored;
	}

	private refreshTokenPayload(tokenData: ApiTokenData): Record<string, unknown> {
		const claims = tokenData as unknown as Record<string, unknown>;
		const { exp: _exp, iat: _iat, nbf: _nbf, ...payload } = claims;
		void _exp;
		void _iat;
		void _nbf;
		delete payload.accessToken;
		delete payload.refreshToken;
		delete payload.userId;
		delete payload.expires;
		delete payload.issuedAt;
		delete payload.lastSeenAt;
		delete payload.status;
		return payload;
	}

	private signRefreshPair(stored: Token, payload: Record<string, unknown>): SignedRefreshPair | null {
		const conf = this.config;
		const access = this.jwtSign(payload, conf.accessSecret, conf.accessExpiry);
		if (!access.success || !access.token) {
			return null;
		}
		const remainingSeconds =
			stored.expires instanceof Date
				? Math.max(1, Math.ceil((stored.expires.getTime() - Date.now()) / 1000))
				: Math.max(1, conf.refreshExpiry);
		const newRefresh = this.jwtSign(payload, conf.refreshSecret, remainingSeconds);
		if (!newRefresh.success || !newRefresh.token) {
			return null;
		}
		return {
			accessToken: access.token,
			refreshToken: newRefresh.token,
			remainingSeconds
		};
	}

	private async replaceStoredRefreshToken(
		stored: Token,
		currentRefreshToken: string,
		pair: SignedRefreshPair
	): Promise<Token | null> {
		let deleted: number;
		try {
			deleted = await this.deleteToken({ refreshToken: currentRefreshToken });
		} catch {
			return null;
		}
		if (deleted === 0) {
			return null;
		}
		const refreshedStored: Token = {
			...stored,
			accessToken: pair.accessToken,
			refreshToken: pair.refreshToken
		};
		try {
			await this.storeToken({
				...refreshedStored,
				lastSeenAt: new Date()
			});
		} catch {
			return null;
		}
		return refreshedStored;
	}

	private async applyRefreshedAccessToken(
		apiReq: ApiRequest,
		stored: Token,
		pair: SignedRefreshPair
	): Promise<RefreshedAccessToken | null> {
		this.setAccessCookie(apiReq, pair.accessToken, stored.sessionCookie ?? false);
		this.setRefreshCookie(apiReq, pair.refreshToken, stored.sessionCookie ?? false, pair.remainingSeconds);
		if (apiReq.req.cookies) {
			apiReq.req.cookies[this.config.accessCookie] = pair.accessToken;
			apiReq.req.cookies[this.config.refreshCookie] = pair.refreshToken;
		}
		const verifiedAccess = await this.verifyJWT(pair.accessToken);
		if (!verifiedAccess.tokenData) {
			return null;
		}
		apiReq.authToken = stored;
		return {
			token: pair.accessToken,
			tokenData: verifiedAccess.tokenData,
			stored
		};
	}

	private async tryRefreshAccessToken(apiReq: ApiRequest): Promise<RefreshedAccessToken | null> {
		const verified = this.readVerifiedRefreshToken(apiReq);
		if (!verified) {
			return null;
		}
		const stored = await this.loadBoundRefreshToken(verified);
		if (!stored) {
			return null;
		}
		const pair = this.signRefreshPair(stored, this.refreshTokenPayload(verified.tokenData));
		if (!pair) {
			return null;
		}
		const refreshedStored = await this.replaceStoredRefreshToken(stored, verified.token, pair);
		return refreshedStored ? this.applyRefreshedAccessToken(apiReq, refreshedStored, pair) : null;
	}

	private bearerToken(req: ExtendedReq): string | null {
		const authHeader = req.headers.authorization;
		const headerValue = Array.isArray(authHeader) ? authHeader[0] : authHeader;
		return headerValue?.startsWith('Bearer ') ? headerValue.slice(7).trim() || null : null;
	}

	private selectAccessToken(
		apiReq: ApiRequest,
		bearerToken: string | null,
		paramToken: string | null
	): string | null {
		if (bearerToken) {
			apiReq.authMethod = 'bearer';
			return bearerToken;
		}
		if (paramToken) {
			apiReq.authMethod = 'param';
			return paramToken;
		}
		const accessCookie = apiReq.req.cookies?.[this.config.accessCookie];
		if (accessCookie) {
			apiReq.authMethod = 'cookie';
			return accessCookie;
		}
		return null;
	}

	private async refreshMissingAccessToken(
		apiReq: ApiRequest,
		authType: ApiAuthType,
		requiresAuthToken: boolean
	): Promise<RefreshedAccessToken | null> {
		if (authType === 'maybe' && !this.config.refreshMaybe) {
			return null;
		}
		const refreshed = await this.tryRefreshAccessToken(apiReq);
		if (refreshed || authType === 'maybe') {
			return refreshed;
		}
		if (requiresAuthToken) {
			throw new ApiError({
				code: 401,
				message: 'Authorization token is required (Bearer/cookie)'
			});
		}
		return null;
	}

	private async verifyOrRefreshAccessToken(
		apiReq: ApiRequest,
		token: string,
		allowRefresh: boolean
	): Promise<AccessTokenState> {
		const verified = await this.verifyJWT(token);
		if (verified.tokenData) {
			return { token, tokenData: verified.tokenData };
		}
		if (allowRefresh && verified.expired) {
			const refreshed = await this.tryRefreshAccessToken(apiReq);
			if (refreshed) {
				return refreshed;
			}
		}
		throw new ApiError({
			code: 401,
			message: 'Unauthorized Access - ' + verified.error
		});
	}

	private applyTokenIdentity(apiReq: ApiRequest, tokenData: ApiTokenData): void {
		const effectiveUserId = this.extractTokenUserId(tokenData);
		apiReq.realUid = this.resolveRealUserId(tokenData, effectiveUserId);
	}

	private canRefreshInvalidStoredToken(error: unknown, allowRefresh: boolean): boolean {
		return (
			allowRefresh &&
			error instanceof ApiError &&
			error.code === 401 &&
			error.message === 'Authorization token is no longer valid'
		);
	}

	private async validateStoredAccessToken(
		apiReq: ApiRequest,
		state: AccessTokenState,
		authType: ApiAuthType,
		allowRefresh: boolean
	): Promise<AccessTokenState> {
		if (!this.shouldValidateStoredToken(authType)) {
			return state;
		}
		try {
			await this.assertStoredAccessToken(apiReq, state.token, state.tokenData);
			return state;
		} catch (error) {
			if (!this.canRefreshInvalidStoredToken(error, allowRefresh)) {
				throw error;
			}
			const refreshed = await this.tryRefreshAccessToken(apiReq);
			if (!refreshed) {
				throw error;
			}
			this.applyTokenIdentity(apiReq, refreshed.tokenData);
			await this.assertStoredAccessToken(apiReq, refreshed.token, refreshed.tokenData);
			return refreshed;
		}
	}

	private allowsAccessTokenRefresh(authType: ApiAuthType): boolean {
		return this.requiresAuthToken(authType) || (authType === 'maybe' && this.config.refreshMaybe);
	}

	private async authenticateApiKeyCandidate(
		apiReq: ApiRequest,
		authType: ApiAuthType,
		tokenCandidate: string | null
	): Promise<ApiTokenData | null> {
		if (!this.config.apiKeyEnabled && authType !== 'apikey') {
			return null;
		}
		return this.tryAuthenticateApiKey(apiReq, authType, tokenCandidate);
	}

	private async initialAccessToken(
		apiReq: ApiRequest,
		authType: ApiAuthType,
		bearerToken: string | null,
		paramToken: string | null
	): Promise<InitialAccessToken | null> {
		const selected = this.selectAccessToken(apiReq, bearerToken, paramToken);
		if (selected) {
			return { token: selected, state: null };
		}
		const refreshed = await this.refreshMissingAccessToken(apiReq, authType, this.requiresAuthToken(authType));
		if (refreshed) {
			return { token: refreshed.token, state: refreshed };
		}
		if (authType === 'maybe') {
			return null;
		}
		throw new ApiError({
			code: 401,
			message: 'Unauthorized Access - requires authentication'
		});
	}

	private async authenticate(apiReq: ApiRequest, authType: ApiAuthType): Promise<ApiTokenData | null> {
		if (authType === 'none') {
			apiReq.realUid = null;
			return null;
		}
		const bearerToken = this.bearerToken(apiReq.req);
		const paramToken = bearerToken ? null : this.resolveTokenFromRequest(apiReq.req);
		const apiKeyAuth = await this.authenticateApiKeyCandidate(apiReq, authType, bearerToken ?? paramToken);
		if (apiKeyAuth) {
			return apiKeyAuth;
		}
		const initial = await this.initialAccessToken(apiReq, authType, bearerToken, paramToken);
		if (!initial) {
			return null;
		}
		const allowRefresh = this.allowsAccessTokenRefresh(authType);
		let state = initial.state ?? (await this.verifyOrRefreshAccessToken(apiReq, initial.token, allowRefresh));
		this.applyTokenIdentity(apiReq, state.tokenData);
		state = await this.validateStoredAccessToken(apiReq, state, authType, allowRefresh);
		apiReq.token = state.token;
		return state.tokenData;
	}

	private async tryAuthenticateApiKey(
		apiReq: ApiRequest,
		authType: ApiAuthType,
		tokenCandidate: string | null
	): Promise<ApiTokenData | null> {
		if (!tokenCandidate) {
			return this.rejectApiKey(authType, 'Authorization header is missing or invalid');
		}
		const secret = this.apiKeySecret(tokenCandidate);
		if (!secret) {
			return this.rejectApiKey(authType, 'Invalid API Key');
		}
		const key = await this.getApiKey(secret);
		if (!key) {
			return this.rejectApiKey(authType, 'Invalid API Key');
		}
		return this.applyApiKeyIdentity(apiReq, secret, key);
	}

	private rejectApiKey(authType: ApiAuthType, message: string): null {
		if (authType === 'apikey') {
			throw new ApiError({ code: 401, message });
		}
		return null;
	}

	private apiKeySecret(tokenCandidate: string): string | null {
		const prefix = this.config.apiKeyPrefix;
		return prefix === ''
			? tokenCandidate
			: tokenCandidate.startsWith(prefix)
				? tokenCandidate.slice(prefix.length)
				: null;
	}

	private applyApiKeyIdentity(apiReq: ApiRequest, secret: string, key: ApiKey): ApiTokenData {
		apiReq.token = secret;
		apiReq.apiKey = key;
		apiReq.authMethod = 'apikey';
		const resolvedRuid = this.normalizeAuthIdentifier(key.uid);
		const resolvedEuid = key.euid !== undefined ? this.normalizeAuthIdentifier(key.euid) : null;
		const effectiveUid = resolvedEuid ?? resolvedRuid;
		if (resolvedRuid !== null) {
			apiReq.realUid = resolvedRuid;
		}
		return {
			uid: effectiveUid,
			...(resolvedEuid !== null
				? {
						ruid: resolvedRuid !== null ? String(resolvedRuid) : undefined
					}
				: {}),
			domain: '',
			fingerprint: '',
			iat: 0,
			exp: 0
		};
	}

	private resolveTokenFromRequest(req: ExtendedReq): string | null {
		const paramName = this.config.tokenParam.trim();
		if (!paramName) {
			return null;
		}
		const location = this.config.tokenParamLocation;
		if (location === 'body') {
			return this.readNamedValue(req.body, paramName);
		}
		if (location === 'query') {
			return this.readNamedValue(req.query, paramName);
		}
		return this.readNamedValue(req.body, paramName) ?? this.readNamedValue(req.query, paramName);
	}

	private readNamedValue(container: unknown, key: string): string | null {
		if (!container || typeof container !== 'object' || Array.isArray(container)) {
			return null;
		}
		const raw = (container as Record<string, unknown>)[key];
		if (typeof raw === 'string') {
			const token = raw.trim();
			return token.length > 0 ? token : null;
		}
		if (Array.isArray(raw)) {
			for (const entry of raw) {
				if (typeof entry === 'string') {
					const token = entry.trim();
					if (token.length > 0) {
						return token;
					}
				}
			}
		}
		return null;
	}

	private requiresAuthToken(authType: ApiAuthType): boolean {
		return authType === 'yes' || authType === 'strict';
	}

	private shouldValidateStoredToken(authType: ApiAuthType): boolean {
		return this.config.validateTokens || authType === 'strict';
	}

	private async assertStoredAccessToken(apiReq: ApiRequest, token: string, tokenData: ApiTokenData): Promise<void> {
		const userId = String(this.extractTokenUserId(tokenData));
		if (apiReq.authToken && apiReq.authToken.accessToken === token && String(apiReq.authToken.userId) === userId) {
			return;
		}
		const stored = await this.getToken({
			accessToken: token,
			userId
		});
		if (!stored) {
			throw new ApiError({
				code: 401,
				message: 'Authorization token is no longer valid'
			});
		}
		apiReq.authToken = stored;
	}

	private normalizeAuthIdentifier(candidate: unknown): AuthIdentifier | null {
		if (typeof candidate === 'number' && Number.isFinite(candidate)) {
			return candidate;
		}
		if (typeof candidate === 'string') {
			const trimmed = candidate.trim();
			if (trimmed.length > 0) {
				return trimmed;
			}
		}
		return null;
	}

	private extractTokenUserId(tokenData: ApiTokenData): AuthIdentifier {
		const normalized = this.normalizeAuthIdentifier(tokenData.uid);
		if (normalized === null) {
			throw new ApiError({
				code: 401,
				message: 'Authorization token is malformed'
			});
		}
		return normalized;
	}

	private resolveRealUserId(tokenData: ApiTokenData, effectiveUserId: AuthIdentifier): AuthIdentifier {
		const withReal = tokenData as ApiTokenData & { ruid?: AuthIdentifier };
		const rawReal = this.normalizeAuthIdentifier(withReal.ruid);
		if (rawReal === null) {
			return effectiveUserId;
		}
		return rawReal;
	}

	private toExtendedReq(request: FastifyRequest): ExpressApiRequest {
		const parsedBody = (request as FastifyRequest & { __apiParsedBody?: unknown }).__apiParsedBody;
		const parsedFiles = (request as FastifyRequest & { __apiParsedFiles?: ApiUploadedFile[] }).__apiParsedFiles;
		const headers = request.headers as Record<string, string | string[] | undefined>;
		const raw = request.raw as IncomingMessage & Partial<ExtendedReq>;
		const originalUrl = request.raw.url;
		raw.method = request.method;
		raw.url = request.url;
		return Object.assign(raw, {
			method: request.method,
			url: request.url,
			originalUrl,
			headers,
			query: (request.query ?? {}) as Record<string, unknown>,
			body: parsedBody ?? request.body,
			params: (request.params ?? {}) as Record<string, unknown>,
			cookies: ((request as unknown as { cookies?: Record<string, string> }).cookies ?? {}) as Record<
				string,
				string
			>,
			ip: request.ip,
			ips: request.ips,
			socket: request.socket,
			protocol: request.protocol,
			raw: request.raw,
			fastifyRequest: request,
			files: parsedFiles
		}) as ExpressApiRequest;
	}

	private createApiRequest(req: ExtendedReq, res: _ApiReply): ApiRequest {
		const apiReq = {
			server: this,
			req,
			res,
			token: '',
			tokenData: null as ApiTokenData | null,
			authMethod: null as ApiAuthMethod,
			realUid: null as AuthIdentifier | null,
			getClientInfo: () => ensureClientInfo(apiReq, this.config.trustProxy),
			getClientIp: () => ensureClientInfo(apiReq, this.config.trustProxy).ip,
			getClientIpChain: () => ensureClientInfo(apiReq, this.config.trustProxy).ipchain,
			getRealUid: () => apiReq.realUid ?? null,
			isImpersonating: () => {
				const realUid = apiReq.realUid;
				const tokenUid = apiReq.tokenData?.uid;
				if (realUid === null || realUid === undefined) {
					return false;
				}
				if (tokenUid === null || tokenUid === undefined) {
					return false;
				}
				// Normalise both sides to strings before comparing so that
				// numeric 42 and string "42" are treated as the same identity.
				return String(realUid) !== String(tokenUid);
			}
		} as ApiRequest;
		return apiReq;
	}

	public useExpress(path: string, ...handlers: Array<CompatRequestHandler | CompatErrorHandler>): this;
	public useExpress(...handlers: Array<CompatRequestHandler | CompatErrorHandler>): this;
	public useExpress(
		pathOrHandler: string | CompatRequestHandler | CompatErrorHandler,
		...handlers: Array<CompatRequestHandler | CompatErrorHandler>
	): this {
		this.assertNotFinalized('useExpress');
		if (typeof pathOrHandler !== 'string') {
			const allHandlers = [pathOrHandler, ...handlers];
			for (const handler of allHandlers) {
				if (handler.length === 4) {
					this.compatGlobalErrorHandler = handler as CompatErrorHandler;
				} else {
					const fn = handler as CompatRequestHandler;
					this.fastify.addHook('preHandler', async (request, reply) => {
						const req = this.toExtendedReq(request);
						const res = new FastifyResponseAdapter(reply);
						await this.runCompatRequestHandler(fn, req, res);
					});
				}
			}
			return this;
		}
		const path = pathOrHandler;
		const stack = handlers;
		this.fastify.all(path, async (request, reply) => {
			const req = this.toExtendedReq(request);
			const res = new FastifyResponseAdapter(reply);
			try {
				await this.runCompatHandlers(stack, req, res);
			} catch (error) {
				await this.runCompatErrorHandlers(error, stack, req, res);
			}
		});
		return this;
	}

	private async runCompatHandlers(
		stack: Array<CompatRequestHandler | CompatErrorHandler>,
		req: ExpressApiRequest,
		res: _ApiReply
	): Promise<void> {
		const handlers = stack.filter((fn) => fn.length !== 4) as CompatRequestHandler[];
		for (const fn of handlers) {
			await this.runCompatRequestHandler(fn, req, res);
			if (res.headersSent) {
				return;
			}
		}
	}

	private async runCompatRequestHandler(
		fn: CompatRequestHandler,
		req: ExpressApiRequest,
		res: _ApiReply
	): Promise<void> {
		await new Promise<void>((resolve, reject) => {
			let nextCalled = false;
			const next: CompatNext = (error?: unknown) => {
				nextCalled = true;
				if (error) {
					reject(error);
					return;
				}
				resolve();
			};
			try {
				const out = fn(req, res, next);
				Promise.resolve(out)
					.then(() => {
						if (!nextCalled) resolve();
					})
					.catch(reject);
			} catch (error) {
				reject(error);
			}
		});
	}

	private async runCompatErrorHandlers(
		error: unknown,
		stack: Array<CompatRequestHandler | CompatErrorHandler>,
		req: ExpressApiRequest,
		res: _ApiReply
	): Promise<void> {
		const errorHandlers = stack.filter((fn) => fn.length === 4) as CompatErrorHandler[];
		if (this.compatGlobalErrorHandler) {
			errorHandlers.push(this.compatGlobalErrorHandler);
		}
		if (errorHandlers.length === 0) {
			throw error;
		}
		let currentError: unknown = error;
		for (const handler of errorHandlers) {
			await new Promise<void>((resolve, reject) => {
				const next: CompatNext = (nextError?: unknown) => {
					if (nextError) {
						currentError = nextError;
					}
					resolve();
				};
				try {
					Promise.resolve(handler(currentError, req, res, next))
						.then(() => resolve())
						.catch(reject);
				} catch (caught) {
					reject(caught);
				}
			});
			if (res.headersSent) {
				return;
			}
		}
		if (!res.headersSent) {
			throw currentError;
		}
	}

	public expressAuth(auth: { type: ApiAuthType; req: ApiAuthClass }): CompatRequestHandler {
		return async (req: ExpressApiRequest, res: _ApiReply, next: CompatNext) => {
			const apiReq = this.createApiRequest(req, res);
			req.apiReq = apiReq;
			(res.locals as ExpressApiLocals).apiReq = apiReq;
			try {
				await this.prepareAuthenticatedRequest(apiReq, auth, req);
				next();
			} catch (error) {
				next(error);
			}
		};
	}

	// Format errors from Express compatibility middleware.
	public expressErrorHandler(): CompatErrorHandler {
		return (error: unknown, _req: ExpressApiRequest, res: _ApiReply, next: CompatNext) => {
			void _req;
			if (res.headersSent) {
				next(error);
				return;
			}
			if (error instanceof ApiError || isApiErrorLike(error)) {
				const apiError = error as ApiErrorLike;
				const errorPayload = this.apiErrorPayload(apiError);
				res.status(apiError.code).json(errorPayload);
				return;
			}
			const status = asHttpStatus(error);
			if (status && status < 500) {
				res.status(status).json(
					this.failurePayload(status, status === 400 ? 'Invalid request payload' : 'Internal server error')
				);
				return;
			}
			res.status(500).json(this.maskedErrorPayload(error));
		};
	}

	private resolveRouteValidator(route: ApiRoute): ResolvedRouteValidator | null {
		if (route.validator === undefined) {
			return null;
		}
		const matches = this.routeValidatorAdapters.filter((adapter) => {
			try {
				return adapter.supports(route.validator, route);
			} catch (error) {
				const message = error instanceof Error ? error.message : guessExceptionText(error);
				throw new Error(
					`Validator adapter "${adapter.name}" failed while checking ${route.method.toUpperCase()} ${route.path}: ${message}`,
					{ cause: error }
				);
			}
		});
		if (matches.length === 0) {
			throw new Error(`No validator adapter matched ${route.method.toUpperCase()} ${route.path}`);
		}
		if (matches.length > 1) {
			const names = matches.map((adapter) => adapter.name).join(', ');
			throw new Error(
				`Multiple validator adapters matched ${route.method.toUpperCase()} ${route.path}: ${names}`
			);
		}
		return { adapter: matches[0], route, contract: route.validator };
	}

	private createRouteValidatorContext(
		resolved: ResolvedRouteValidator,
		apiReq: ApiRequest,
		request: FastifyRequest,
		reply: FastifyReply
	): ApiRouteValidatorContext {
		return {
			route: resolved.route,
			contract: resolved.contract,
			apiReq,
			request,
			reply
		};
	}

	private async runRouteValidator(
		resolved: ResolvedRouteValidator,
		apiReq: ApiRequest,
		request: FastifyRequest,
		reply: FastifyReply
	): Promise<void> {
		await resolved.adapter.validate(this.createRouteValidatorContext(resolved, apiReq, request, reply));
	}

	private async prepareAuthenticatedRequest(
		apiReq: ApiRequest,
		auth: { type: ApiAuthType; req: ApiAuthClass },
		hydrateReq: ExtendedReq,
		routeValidator?: ResolvedRouteValidator | null,
		request?: FastifyRequest,
		reply?: FastifyReply
	): Promise<void> {
		if (this.config.hydrateGetBody) {
			hydrateGetBody(hydrateReq);
		}
		if (routeValidator && request && reply) {
			await this.runRouteValidator(routeValidator, apiReq, request, reply);
		}
		if (this.config.debug) {
			this.dumpRequest(apiReq);
		}
		apiReq.tokenData = await this.authenticate(apiReq, auth.type);
		await this.authorize(apiReq, auth.req);
	}

	private normalizeRouteValidatorError(
		resolved: ResolvedRouteValidator,
		error: unknown,
		apiReq: ApiRequest,
		request: FastifyRequest,
		reply: FastifyReply
	): unknown {
		if (error instanceof ApiError || isApiErrorLike(error)) {
			return error;
		}
		if (typeof resolved.adapter.normalizeError !== 'function') {
			return error;
		}
		const normalized = resolved.adapter.normalizeError(
			error,
			this.createRouteValidatorContext(resolved, apiReq, request, reply)
		);
		return normalized ? new ApiError(normalized) : error;
	}

	private handlerResponsePayload(handlerResult: unknown): ApiResponsePayload {
		if (!Array.isArray(handlerResult)) {
			throw new ApiError({
				code: 500,
				message: 'Handler result must be an array: [status, data?, message?]'
			});
		}
		const [code, data = null, rawMessage = 'Success'] = handlerResult;
		if (typeof code !== 'number' || Number.isNaN(code)) {
			throw new ApiError({
				code: 500,
				message: 'Handler result must start with a numeric status code'
			});
		}
		return {
			success: code < 400,
			code,
			message: typeof rawMessage === 'string' ? rawMessage : 'Success',
			data,
			errors: {}
		};
	}

	private sendRoutePayload(apiReq: ApiRequest, reply: FastifyReply, payload: ApiResponsePayload): void {
		if (this.config.debug) {
			this.dumpResponse(apiReq, payload, payload.code);
		}
		reply.code(payload.code).send(payload);
	}

	private isUploadLimitError(error: unknown): boolean {
		return (
			error !== null &&
			typeof error === 'object' &&
			'code' in error &&
			(error as { code?: unknown }).code === 'FST_REQ_FILE_TOO_LARGE'
		);
	}

	// Preserve request statuses and mask unexpected server errors.
	private unexpectedRouteErrorPayload(error: unknown): ApiResponsePayload {
		if (this.isUploadLimitError(error)) {
			return this.failurePayload(413, `Upload exceeds maximum size of ${this.config.uploadMax} bytes`);
		}
		const status = asHttpStatus(error);
		return status && status < 500
			? this.failurePayload(status, status === 400 ? 'Invalid request payload' : 'Internal server error')
			: this.maskedErrorPayload(error);
	}

	private routeErrorPayload(
		error: unknown,
		apiReq: ApiRequest,
		request: FastifyRequest,
		reply: FastifyReply,
		routeValidator?: ResolvedRouteValidator | null
	): ApiResponsePayload {
		const normalizedError = routeValidator
			? this.normalizeRouteValidatorError(routeValidator, error, apiReq, request, reply)
			: error;
		return normalizedError instanceof ApiError || isApiErrorLike(normalizedError)
			? this.apiErrorPayload(normalizedError as ApiErrorLike)
			: this.unexpectedRouteErrorPayload(normalizedError);
	}

	// Resolve trusted identities and enforce quotas without swallowing store failures.
	private async enforceRateLimit(policyName: string | false | undefined, apiReq: ApiRequest): Promise<void> {
		if (policyName === undefined || policyName === false) {
			return;
		}
		const policy = this.rateLimiter.getPolicy(policyName);
		const identity = policy.identity === 'ip' ? apiReq.getClientIp() : apiReq.getRealUid();
		if (identity === null || identity === undefined || String(identity).trim() === '') {
			throw new ApiError({ code: 401, message: 'Rate limit identity is unavailable' });
		}
		const decision = await this.rateLimiter.consume(policyName, String(identity));
		if (!decision.allowed) {
			throw new ApiError({
				code: 429,
				message: 'Too many requests',
				data: { retryAfterSec: decision.retryAfterSec }
			});
		}
	}

	// Apply global quotas before authentication and route quotas before executing the handler.
	private async executeApiRequest(
		handler: ApiHandler,
		auth: { type: ApiAuthType; req: ApiAuthClass },
		request: FastifyRequest,
		reply: FastifyReply,
		routeValidator?: ResolvedRouteValidator | null,
		rateLimit?: string | false
	): Promise<void> {
		const req = this.toExtendedReq(request);
		const apiReq = this.createApiRequest(req, new FastifyResponseAdapter(reply));
		try {
			await this.enforceRateLimit(this.config.rateLimits?.global, apiReq);
			await this.prepareAuthenticatedRequest(apiReq, auth, apiReq.req, routeValidator, request, reply);
			await this.enforceRateLimit(rateLimit, apiReq);
			const payload = this.handlerResponsePayload(await handler(apiReq));
			this.sendRoutePayload(apiReq, reply, payload);
		} catch (error) {
			const payload = this.routeErrorPayload(error, apiReq, request, reply, routeValidator);
			this.sendRoutePayload(apiReq, reply, payload);
		}
	}

	// Carry route policy selection into the centralized API request pipeline.
	private handleRequest(
		handler: ApiHandler,
		auth: { type: ApiAuthType; req: ApiAuthClass },
		routeValidator?: ResolvedRouteValidator | null,
		rateLimit?: string | false
	) {
		return (request: FastifyRequest, reply: FastifyReply) =>
			this.executeApiRequest(handler, auth, request, reply, routeValidator, rateLimit);
	}

	// Test/compat shim for direct unit-level request wrapping without Fastify runtime.
	protected handle_request(handler: ApiHandler, auth: { type: ApiAuthType; req: ApiAuthClass }) {
		return async (req: ExtendedReq, res: _ApiReply, next: (error?: unknown) => void) => {
			const apiReq = this.createApiRequest(req, res);
			try {
				if (this.config.hydrateGetBody) {
					hydrateGetBody(apiReq.req);
				}
				apiReq.tokenData = await this.authenticate(apiReq, auth.type);
				await this.authorize(apiReq, auth.req);
				await handler(apiReq);
				next();
			} catch (error) {
				next(error);
			}
		};
	}

	public api<T extends ApiModule<unknown>>(module: T, options: { signer?: RequestSigner | false } = {}): this {
		this.assertNotFinalized('api');

		module.server = this;
		const moduleType = (module as ModuleWithType).moduleType;
		if (moduleType === 'auth') {
			this.authModule(module as unknown as AuthProviderModule<unknown>);
		}

		const configOk = module.checkConfig();
		if (configOk === false) {
			const name = module.constructor?.name ? String(module.constructor.name) : 'ApiModule';
			throw new Error(`${name}.checkConfig() returned false`);
		}
		module.onMount();

		const ns = module.namespace;
		const mountPath = `${this.apiBasePath}${ns}`;
		module.mountpath = mountPath;
		if (moduleType === 'auth') {
			this.registerOpenApiPathPrefix('/api/auth', mountPath);
		}

		for (const route of module.defineRoutes()) {
			const routeValidator = this.resolveRouteValidator(route);
			if (route.rateLimit !== undefined && route.rateLimit !== false) {
				this.rateLimiter.getPolicy(route.rateLimit);
			}
			const handler = this.handleRequest(route.handler, route.auth, routeValidator, route.rateLimit);
			const method = route.method.toUpperCase() as HTTPMethods;
			const fullPath = this.joinRoutePath(this.apiBasePath, ns, route.path);
			const schema = applyRouteSchemaDefaults(route.schema, {
				strictProps: route.strictProps
			});
			const signer = route.signer ?? options.signer ?? module.signer ?? this.config.signer ?? false;
			this.fastify.route({
				method,
				url: fullPath,
				handler,
				config: {
					apiCoreParseMultipart: true,
					apiCoreSigner: signer
				} as ApiCoreRouteConfig,
				...(schema ? { schema } : {})
			});
			if (this.config.debug) {
				console.log(`Adding ${fullPath} (${method})`);
			}
		}

		return this;
	}

	private joinRoutePath(base: string, namespace: string, routePath: string): string {
		const parts = [base, namespace, routePath]
			.filter((value) => typeof value === 'string' && value.length > 0)
			.map((value, index) => {
				if (index === 0) {
					return value.startsWith('/') ? value : `/${value}`;
				}
				return value.replace(/^\/+/, '').replace(/\/+$/, '');
			});
		const joined = parts.join('/').replace(/\/+/g, '/');
		return joined.startsWith('/') ? joined : `/${joined}`;
	}

	public dumpRequest(apiReq: ApiRequest) {
		const req = apiReq.req;
		const sensitiveKeys = this.debugSensitiveKeys();
		console.log('--- Incoming Request! ---');
		console.log('URL:', req.originalUrl || req.url);
		console.log('Method:', req.method);
		console.log('Query Params:', redactDebugValue(req.query || {}, sensitiveKeys));
		console.log('Body Params:', redactDebugValue(req.body || {}, sensitiveKeys));
		console.log('Cookies:', this.redactDebugCookies(req.cookies));
		console.log('Headers:', this.redactDebugHeaders(req.headers));
		console.log('------------------------');
	}

	private debugSensitiveKeys(): Set<string> {
		const sensitiveKeys = new Set(DEFAULT_DEBUG_SENSITIVE_KEYS);
		const tokenParam = this.config.tokenParam.trim();
		if (tokenParam) {
			sensitiveKeys.add(tokenParam.toLowerCase());
		}
		return sensitiveKeys;
	}

	private redactDebugCookies(cookiesValue: Record<string, string> | undefined): Record<string, string> {
		const cookies = cookiesValue ? { ...cookiesValue } : {};
		for (const key of [this.config.accessCookie, this.config.refreshCookie]) {
			if (key in cookies) {
				cookies[key] = '[REDACTED]';
			}
		}
		return cookies;
	}

	private redactDebugHeaders(headersValue: Record<string, unknown>): Record<string, unknown> {
		const headers = { ...headersValue };
		if (headers.authorization) {
			headers.authorization = '[REDACTED]';
		}
		if (headers['x-api-key']) {
			headers['x-api-key'] = '[REDACTED]';
		}
		if (headers.cookie) {
			headers.cookie = '[REDACTED]';
		}
		return headers;
	}

	private formatDebugValue(value: unknown, maxLength = 50, seen: WeakSet<object> = new WeakSet()): unknown {
		if (value === null || value === undefined) {
			return value;
		}
		switch (typeof value) {
			case 'string':
				return value.length <= maxLength
					? value
					: `${value.slice(0, maxLength)}… [truncated ${value.length - maxLength} chars]`;
			case 'symbol':
				return value.toString();
			case 'function':
				return `[Function ${value.name || 'anonymous'}]`;
			case 'object':
				return this.formatDebugObject(value, maxLength, seen);
			default:
				return value;
		}
	}

	private formatDebugObject(value: object, maxLength: number, seen: WeakSet<object>): unknown {
		if (value instanceof Date) {
			return value.toISOString();
		}
		if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) {
			return `<Buffer length=${value.length}>`;
		}
		if (seen.has(value)) {
			return '[Circular]';
		}
		seen.add(value);
		const formatted = Array.isArray(value)
			? value.map((item) => this.formatDebugValue(item, maxLength, seen))
			: Object.fromEntries(
					Object.entries(value).map(([key, entry]) => [key, this.formatDebugValue(entry, maxLength, seen)])
				);
		seen.delete(value);
		return formatted;
	}

	public dumpResponse(apiReq: ApiRequest, payload: unknown, status: number) {
		const rawUrl = apiReq.req.originalUrl || apiReq.req.url;
		const tokenParam = this.config.tokenParam.trim();
		let url = rawUrl;
		if (tokenParam && rawUrl) {
			try {
				const parsed = new URL(rawUrl, 'http://x');
				if (parsed.searchParams.has(tokenParam)) {
					parsed.searchParams.set(tokenParam, '[REDACTED]');
					url = parsed.pathname + '?' + parsed.searchParams.toString();
				}
			} catch {
				// Leave url unmodified if parsing fails
			}
		}
		console.log('--- Outgoing Response! ---');
		console.log('URL:', url);
		console.log('Status:', status);
		// Redact before formatting: truncation is not redaction, and short secrets
		// (API keys, opaque tokens) would otherwise be logged in full.
		console.log('Payload:', this.formatDebugValue(redactDebugValue(payload, this.debugSensitiveKeys())));
		console.log('--------------------------');
	}
}

export default ApiServer;
