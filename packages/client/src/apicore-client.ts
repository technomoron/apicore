/**
 * Copyright (c) 2025 Bjørn Erik Jacobsen / Technomoron
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { DEBUG_REDACTED_VALUE, redactDebugValue } from './debug.js';

import type {
	ApiLoginRes,
	ApiLogoutRes,
	ApiMeRes,
	ApiPingRes,
	ApiRefreshRes,
	ApiResponse as ApiResponseEnvelope,
	ApiRevokeSessionRes,
	ApiSessionsRes
} from './common.js';
import type { RequestSigner } from './request-signing.js';

export type {
	ApiLoginRes,
	ApiLogoutRes,
	ApiMeRes,
	ApiOAuthAuthorizeRes,
	ApiOAuthCallbackRes,
	ApiOAuthStartRes,
	ApiOAuthTokenRes,
	ApiPasskeyChallengeRes,
	ApiPasskeyCredential,
	ApiPasskeyDeleteRes,
	ApiPasskeyListRes,
	ApiPasskeyVerifyRes,
	ApiPingRes,
	ApiRefreshRes,
	ApiRevokeSessionRes,
	ApiSessionsRes,
	AuthIdentifier,
	SafeUser,
	SessionInfo,
	TokenStatus
} from './common.js';

export type maybeFile = File | Blob | [string, File | Blob];

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

type SerializableBody = JsonValue;

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const DEBUG_SENSITIVE_KEYS = new Set([
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

function summarizeDebugFormData(value: unknown): { handled: true; value: Record<string, unknown> } | undefined {
	if (typeof FormData !== 'undefined' && value instanceof FormData) {
		const summary: Record<string, unknown> = {};
		for (const [key, entry] of value.entries()) {
			if (DEBUG_SENSITIVE_KEYS.has(key.toLowerCase())) {
				summary[key] = DEBUG_REDACTED_VALUE;
				continue;
			}
			summary[key] = typeof entry === 'string' ? entry : '[Blob]';
		}
		return { handled: true, value: summary };
	}
	return undefined;
}

function sanitizeDebugValue(value: unknown): unknown {
	return redactDebugValue(value, {
		sensitiveKeys: DEBUG_SENSITIVE_KEYS,
		isRecord: isPlainObject,
		summarize: summarizeDebugFormData
	});
}

function sanitizeDebugHeaders(headers: Headers): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [key, value] of headers.entries()) {
		out[key] =
			DEBUG_SENSITIVE_KEYS.has(key.toLowerCase()) || key.toLowerCase() === 'cookie'
				? DEBUG_REDACTED_VALUE
				: value;
	}
	return out;
}

function getErrorMessage(error: unknown): string | undefined {
	if (error instanceof Error) {
		return error.message || undefined;
	}

	if (isPlainObject(error)) {
		const potentialMessage = error['message'];
		if (typeof potentialMessage === 'string') {
			return potentialMessage;
		}
	}

	return undefined;
}

function getErrorCode(error: unknown): string | undefined {
	if (isPlainObject(error)) {
		const potentialCode = error['code'];
		if (typeof potentialCode === 'string') {
			return potentialCode;
		}
	}

	return undefined;
}

function hasErrorName(error: unknown, expected: string): boolean {
	if (isPlainObject(error)) {
		const potentialName = error['name'];
		if (typeof potentialName === 'string') {
			return potentialName === expected;
		}
	}

	return false;
}

function normalizeApiBasePath(value: string): string {
	const trimmed = value.trim();
	if (!trimmed || trimmed === '/') {
		return '/';
	}
	return `/${trimmed.replace(/^\/+/, '').replace(/\/+$/, '')}`;
}

export interface ApiClientConfig {
	apiKey?: string | null;
	/** Optional request signer. */
	signer?: RequestSigner | null;
	timeout?: number;
	maxRetries?: number;
	debug?: boolean;
	enableTokens?: boolean;
	/**
	 * Base path for auth endpoints. Defaults to `/api/auth/v1`.
	 * Change this when the server is configured with a custom `apiBasePath` or AuthModule namespace.
	 */
	authBasePath?: string;
	/** Base path for core endpoints such as `ping`. Defaults to `/api`. */
	apiBasePath?: string;
}

/**
 * Define the shape of the raw JSON coming back from the API
 * This represents the optional/partial structure before we normalize it into ApiResponse
 */
type RawApiResponse<T = unknown> = Partial<ApiResponseEnvelope<T>>;
type FetchAttempt<T> = { kind: 'complete'; response: ApiResponse<T> } | { kind: 'retry-after-refresh' };

/**
 * Parses an error message from various error types
 * @param {unknown} error - The error to parse
 * @param {string} def - Default message if no message can be extracted
 * @returns {string} The extracted error message or default message
 */
function parseMessage(error: unknown, def: string = ''): string {
	if (typeof error === 'string') {
		return error;
	}

	const message = getErrorMessage(error);
	if (message) {
		return message;
	}

	return def || '[Unknown error type - neither string, Error nor has .message]';
}

export class ApiResponse<T = unknown> implements ApiResponseEnvelope<T> {
	success: boolean = false;
	code: number = 500;
	message: string = '[No Message]';
	data: T | null = null;
	errors: Record<string, string> = {};

	constructor(response: Partial<ApiResponseEnvelope<T>> = {}) {
		this.success = response.success ?? false;
		this.code = response.code ?? 500;
		this.message = parseMessage(response.message, '[No Message]');
		this.data = response.data ?? null;
		this.errors = response.errors ?? {};
	}

	/**
	 * Creates a successful response with the provided data
	 * @param {T} data - The response data
	 * @param {Partial<ApiResponse<T>>} overrides - Optional overrides for response properties
	 * @returns {ApiResponse<T>} A configured successful response
	 */
	static ok<T>(data: T, overrides: Partial<Omit<ApiResponseEnvelope<T>, 'data'>> = {}): ApiResponse<T> {
		return new ApiResponse<T>({
			success: true,
			code: 200,
			message: 'OK',
			data,
			...overrides
		});
	}

	/**
	 * Creates an error response with the provided message
	 * @param {unknown} messageOrError - The error message, error object, or existing ApiResponse
	 * @param {Partial<ApiResponse<T>>} overrides - Optional overrides for response properties
	 * @returns {ApiResponse<T>} A configured error response
	 */
	static error<T>(
		messageOrError: unknown,
		overrides: Partial<Omit<ApiResponseEnvelope<T>, 'data'>> = {}
	): ApiResponse<T> {
		if (messageOrError instanceof ApiResponse) {
			return messageOrError;
		}

		// Use parseMessage to handle any error type consistently
		const message = parseMessage(messageOrError, 'Unknown error');

		return new ApiResponse<T>({
			success: false,
			code: overrides.code ?? 500,
			message,
			data: null,
			...overrides
		}) as unknown as ApiResponse<T>;
	}

	/**
	 * Adds a named error to the errors collection
	 * @param {string} name - The name/key for the error
	 * @param {string} value - The error message
	 */
	addError(name: string, value: string): void {
		this.errors[name] = value;
	}

	/**
	 * Type guard to check if the response is successful and contains data
	 * When this returns true, TypeScript narrows the type to ensure data is not null
	 * @returns {boolean} True if the response is successful and contains data
	 */
	isSuccess(): this is ApiResponse<T> & { data: T } {
		return this.success && this.data !== null;
	}
}

function isBrowserRuntime(): boolean {
	return (
		typeof window !== 'undefined' && typeof (window as unknown as { document?: unknown }).document !== 'undefined'
	);
}

function browserFetchFailure(error: unknown): { reason: string; status: number } {
	if (error instanceof TypeError && error.message === 'Failed to fetch') {
		return {
			reason: 'Possible CORS issue or server unreachable',
			status: 503
		};
	}
	return {
		reason: getErrorMessage(error) || 'Unknown browser fetch error',
		status: 500
	};
}

function nodeFetchFailure(error: unknown): { reason: string; status: number } {
	switch (getErrorCode(error)) {
		case 'ECONNREFUSED':
			return { reason: 'Connection refused by server', status: 503 };
		case 'ENOTFOUND':
			return { reason: 'DNS lookup failed - host not found', status: 503 };
		case 'ETIMEDOUT':
			return { reason: 'Connection timed out', status: 504 };
		case 'ECONNRESET':
			return { reason: 'Connection reset by server', status: 503 };
		case 'EHOSTUNREACH':
			return { reason: 'Host unreachable', status: 503 };
		default:
			return { reason: getErrorMessage(error) || 'Unknown network error', status: 500 };
	}
}

function fetchFailure(error: unknown): ApiResponse<never> {
	const failure = isBrowserRuntime() ? browserFetchFailure(error) : nodeFetchFailure(error);
	return ApiResponse.error(`Fetch failed: ${failure.reason}`, {
		code: failure.status
	});
}

class ApiClient {
	private apiKey: string | null = null;
	private signer: RequestSigner | null = null;
	private aToken: string | null = null;
	private rToken: string | null = null;
	private apiUrl: string;
	private authBasePath: string;
	private apiBasePath: string;
	// Shared promise so that concurrent 401s all await the same refresh attempt.
	private _refreshPromise: Promise<ApiResponse<ApiRefreshRes>> | null = null;
	private timeoutMs: number = 15_000;
	private maxRetries: number = 1;
	private debug: boolean = false;
	private tokens: boolean = true;

	constructor(apiUrl: string, config: ApiClientConfig = {}) {
		this.apiUrl = apiUrl.endsWith('/') ? apiUrl.slice(0, -1) : apiUrl;
		this.authBasePath = config.authBasePath ?? '/api/auth/v1';
		this.apiBasePath = normalizeApiBasePath(config.apiBasePath ?? '/api');
		this.apiKey = config.apiKey ?? null;
		this.signer = config.signer ?? null;
		this.timeoutMs = config.timeout ?? 15_000;
		this.maxRetries = config.maxRetries ?? 1;
		this.debug = config.debug ?? false;
		this.tokens = config.enableTokens ?? true;
	}

	/**
	 * Updates the client configuration
	 * @param {Partial<ApiClientConfig>} config - Configuration updates
	 */
	public configure(config: Partial<ApiClientConfig>): void {
		if (config.apiKey !== undefined) this.apiKey = config.apiKey;
		if (config.signer !== undefined) this.signer = config.signer;
		if (config.timeout !== undefined && config.timeout !== null) this.timeoutMs = config.timeout;
		if (config.maxRetries !== undefined && config.maxRetries !== null) this.maxRetries = config.maxRetries;
		if (config.debug !== undefined && config.debug !== null) this.debug = config.debug;
		if (config.enableTokens !== undefined && config.enableTokens !== null) this.tokens = config.enableTokens;
		if (config.authBasePath !== undefined && config.authBasePath !== null) this.authBasePath = config.authBasePath;
		if (config.apiBasePath !== undefined && config.apiBasePath !== null) {
			this.apiBasePath = normalizeApiBasePath(config.apiBasePath);
		}
	}

	/**
	 * Gets the current configuration
	 * @returns {ApiClientConfig} Current configuration
	 */
	public getConfig(): ApiClientConfig {
		return {
			// Omit the raw API key — return a boolean sentinel so callers can check
			// whether a key is configured without being able to extract its value.
			apiKey: this.apiKey ? '***' : null,
			timeout: this.timeoutMs,
			maxRetries: this.maxRetries,
			debug: this.debug,
			enableTokens: this.tokens,
			authBasePath: this.authBasePath,
			apiBasePath: this.apiBasePath
		};
	}

	private tryStringify(obj: SerializableBody): string {
		try {
			return JSON.stringify(obj);
		} catch (err: unknown) {
			if (this.debug) {
				console.error('[ApiClient] JSON.stringify failed:', err);
			}
			throw ApiResponse.error('Failed to serialize request body', {
				code: 400
			});
		}
	}

	/**
	 * Retrieves the stored access token
	 * Designed to be overridden in subclasses for custom token storage
	 * @returns {string|null} The current access token or null if not set
	 */
	get_access_token(): string | null {
		return this.aToken;
	}

	/**
	 * Stores the access token
	 * Designed to be overridden in subclasses for custom token storage
	 * @param {string|null} access - The access token to store, or null to clear
	 */
	set_access_token(access: string | null): void {
		this.aToken = access;
	}

	/**
	 * Retrieves the stored refresh token
	 * Designed to be overridden in subclasses for custom token storage
	 * @returns {string|null} The current refresh token or null if not set
	 */
	get_refresh_token(): string | null {
		return this.rToken;
	}

	/**
	 * Stores the refresh token
	 * Designed to be overridden in subclasses for custom token storage
	 * @param {string|null} refresh - The refresh token to store, or null to clear
	 */
	set_refresh_token(refresh: string | null): void {
		this.rToken = refresh;
	}

	/**
	 * Sets the API key for authentication
	 * Designed to be overridden in subclasses for custom API key storage
	 * @param {string|null} apikey - The API key to use for authentication, or null to clear
	 */
	set_apikey(apikey: string | null): void {
		this.apiKey = apikey;
	}

	/**
	 * Retrieves the stored API key
	 * Designed to be overridden in subclasses for custom API key storage
	 * @returns {string|null} The current API key or null if not set
	 */
	get_apikey(): string | null {
		return this.apiKey;
	}

	/**
	 * Builds authentication headers based on current configuration
	 * @returns {Record<string, string>} Headers object with authentication if available
	 */
	private buildAuthHeaders(): Record<string, string> {
		const headers: Record<string, string> = {};

		if (this.apiKey) {
			headers.Authorization = `Bearer ${this.apiKey}`;
		} else if (this.tokens) {
			const accessToken = this.get_access_token();
			if (accessToken) {
				headers.Authorization = `Bearer ${accessToken}`;
			}
		}

		return headers;
	}

	private prepareFetchHeaders(init: RequestInit): Headers {
		const headers = new Headers(init.headers);
		for (const [key, value] of Object.entries(this.buildAuthHeaders())) {
			headers.set(key, value);
		}
		const method = (init.method ?? 'GET').toUpperCase();
		if (
			method !== 'GET' &&
			init.body !== undefined &&
			init.body !== null &&
			!headers.has('Content-Type') &&
			!(init.body instanceof FormData)
		) {
			headers.set('Content-Type', 'application/json');
		}
		return headers;
	}

	private logFetch(input: RequestInfo, method: string, headers: Headers): void {
		if (!this.debug) {
			return;
		}
		console.log('[safeFetch] Request:', input);
		console.log('[safeFetch] Method:', method);
		console.log('[safeFetch] Headers:', sanitizeDebugHeaders(headers));
	}

	/**
	 * A drop‑in replacement for fetch() that handles timeouts and
	 * normalized network errors and throws an ApiResponse on failure.
	 * Uses the instance's configured timeout value.
	 */
	private async safeFetch(input: RequestInfo, init: RequestInit = {}): Promise<Response> {
		const controller = new AbortController();
		const headers = this.prepareFetchHeaders(init);
		let signed: { input: RequestInfo; body: BodyInit | null | undefined };
		try {
			signed = this.signer ? await this.signer.apply(input, init, headers) : { input, body: init.body };
		} catch (error) {
			throw ApiResponse.error(error, { code: 400 });
		}
		const id = setTimeout(() => controller.abort(), this.timeoutMs);
		const method = (init.method ?? 'GET').toUpperCase();
		this.logFetch(input, method, headers);
		try {
			return await fetch(signed.input, {
				...init,
				body: signed.body,
				headers,
				signal: controller.signal
			});
		} catch (err: unknown) {
			if (hasErrorName(err, 'AbortError')) {
				throw ApiResponse.error('Fetch timed out', { code: 504 });
			}
			throw fetchFailure(err);
		} finally {
			clearTimeout(id);
		}
	}

	/**
	 * Safely parses JSON response with proper error handling
	 * @param {Response} response - The fetch response
	 * @returns {Promise<RawApiResponse<T>>} The parsed JSON data
	 */
	private async parseJsonResponse<T>(response: Response): Promise<RawApiResponse<T>> {
		try {
			return (await response.json()) as RawApiResponse<T>;
		} catch (err: unknown) {
			throw ApiResponse.error(`Failed to parse JSON response: ${parseMessage(err)}`, {
				code: response.status
			});
		}
	}

	private updateStoredTokens(tokenData: ApiRefreshRes | null | undefined): void {
		if (tokenData?.accessToken !== undefined) {
			this.set_access_token(tokenData.accessToken ?? null);
		}
		if (tokenData?.refreshToken !== undefined) {
			this.set_refresh_token(tokenData.refreshToken ?? null);
		}
	}

	async login<T = ApiLoginRes>(
		username: string,
		password: string,
		domain: string = '',
		fingerprint: string = ''
	): Promise<ApiResponse<T>> {
		try {
			const loginBody: Record<string, string> = {
				login: username,
				password
			};
			if (domain) loginBody.domain = domain;
			if (fingerprint) loginBody.fingerprint = fingerprint;
			const response = await this.safeFetch(`${this.apiUrl}${this.authBasePath}/login`, {
				method: 'POST',
				body: this.tryStringify(loginBody),
				credentials: 'include'
			});

			const jsondata = await this.parseJsonResponse<T>(response);

			if (this.debug) {
				console.log('Login Response Headers:');
				response.headers.forEach((value, name) => {
					console.log(`${name}: ${value}`);
				});
			}

			if (response.ok) {
				// Type-safe access to token data — only update tokens when explicitly present
				this.updateStoredTokens(jsondata.data as ApiRefreshRes);

				return ApiResponse.ok(jsondata.data as T, {
					message: jsondata.message || 'Login successful',
					code: response.status
				});
			} else {
				return ApiResponse.error(jsondata.message || 'Login Failed', {
					code: response.status,
					errors: jsondata.errors || {}
				});
			}
		} catch (e: unknown) {
			if (e instanceof ApiResponse) {
				return e;
			}
			return ApiResponse.error(e);
		}
	}

	async logout<T = ApiLogoutRes>(token: string = ''): Promise<ApiResponse<T>> {
		// Read the stored refresh token before clearing local state so cookieless
		// clients can still ask the server to revoke it.
		const refreshToken = token || this.get_refresh_token() || '';
		try {
			const response = await this.safeFetch(`${this.apiUrl}${this.authBasePath}/logout`, {
				method: 'POST',
				body: refreshToken ? this.tryStringify({ token: refreshToken }) : '{}',
				credentials: 'include'
			});

			const jsondata = await this.parseJsonResponse<T>(response);

			if (this.debug) {
				console.log('Logout Response Headers:');
				response.headers.forEach((value, name) => {
					console.log(`${name}: ${value}`);
				});
			}

			if (!response.ok) {
				return ApiResponse.error(jsondata.message || 'Logout Failed', {
					code: response.status,
					errors: jsondata.errors || {}
				});
			}

			return ApiResponse.ok(jsondata.data as T, {
				message: jsondata.message || 'Logout Successful',
				code: response.status
			});
		} catch (e: unknown) {
			if (e instanceof ApiResponse) {
				return e;
			}
			return ApiResponse.error(e);
		} finally {
			this.set_access_token(null);
			this.set_refresh_token(null);
		}
	}

	private async refreshAccessToken<T = ApiRefreshRes>(): Promise<ApiResponse<T>> {
		// Serialise concurrent refresh attempts: if a refresh is already in flight,
		// await it instead of launching a second one (which would fail because the
		// server rotates the refresh token on every use).
		if (this._refreshPromise) {
			return this._refreshPromise as Promise<ApiResponse<T>>;
		}
		this._refreshPromise = this.performRefresh();
		try {
			return (await this._refreshPromise) as ApiResponse<T>;
		} finally {
			this._refreshPromise = null;
		}
	}

	private async performRefresh(): Promise<ApiResponse<ApiRefreshRes>> {
		try {
			if (!this.get_refresh_token()) {
				return ApiResponse.error('No Refresh Token Available', {
					code: 401
				});
			}

			const response = await this.safeFetch(`${this.apiUrl}${this.authBasePath}/refresh`, {
				method: 'POST',
				body: this.tryStringify({
					refreshToken: this.get_refresh_token()
				}),
				credentials: 'include'
			});

			const jsondata = await this.parseJsonResponse<ApiRefreshRes>(response);

			if (!response.ok) {
				// Clear stale tokens when the server rejects the refresh token.
				if (response.status === 401 || response.status === 403) {
					this.set_access_token(null);
					this.set_refresh_token(null);
				}
				return ApiResponse.error(jsondata.message || 'Token Refresh Failed', {
					code: response.status,
					errors: jsondata.errors || {}
				});
			}

			// Only update tokens when the field is explicitly present in the response.
			this.updateStoredTokens(jsondata.data);

			return ApiResponse.ok(jsondata.data as ApiRefreshRes, {
				message: jsondata.message || 'Token Refreshed',
				code: response.status
			});
		} catch (e: unknown) {
			if (e instanceof ApiResponse) {
				return e;
			}
			return ApiResponse.error(e);
		}
	}

	private successfulApiResponse<T>(response: Response, payload: RawApiResponse<T>): ApiResponse<T> {
		if (payload.success === false) {
			return ApiResponse.error(payload.message || 'Request failed', {
				code: payload.code ?? response.status,
				errors: payload.errors || {}
			});
		}
		return ApiResponse.ok<T>(payload.data as T, {
			message: payload.message || 'OK',
			code: payload.code ?? response.status,
			errors: payload.errors || {}
		});
	}

	private failedApiResponse<T>(
		response: Response,
		payload: RawApiResponse<T>,
		fallbackMessage: string
	): ApiResponse<T> {
		return ApiResponse.error(payload.message || fallbackMessage, {
			code: response.status,
			errors: payload.errors || {}
		});
	}

	private async refreshUnauthorizedRequest<T>(): Promise<ApiResponse<T> | null> {
		if (this.debug) {
			console.log('Received 401, attempting token refresh...');
		}
		const refreshResponse = await this.refreshAccessToken<ApiRefreshRes>();
		if (refreshResponse.success) {
			return null;
		}
		return ApiResponse.error<T>(refreshResponse.message, {
			code: refreshResponse.code,
			errors: refreshResponse.errors
		});
	}

	private shouldRetryTimeout(error: unknown, timeoutRetryCount: number): boolean {
		return error instanceof ApiResponse && error.code === 504 && timeoutRetryCount < this.maxRetries;
	}

	private logTimeoutRetry(timeoutRetryCount: number): void {
		if (!this.debug) {
			return;
		}
		console.log(`Request timed out, retrying... (attempt ${timeoutRetryCount + 1}/${this.maxRetries + 1})`);
	}

	private requestError<T>(error: unknown): ApiResponse<T> {
		return error instanceof ApiResponse ? (error as ApiResponse<T>) : ApiResponse.error<T>(error);
	}

	private async fetchAttempt<T>(url: string, init: RequestInit, allowAuthRetry: boolean): Promise<FetchAttempt<T>> {
		const response = await this.safeFetch(url, {
			...init,
			credentials: 'include'
		});
		const payload = await this.parseJsonResponse<T>(response);
		if (response.ok) {
			return { kind: 'complete', response: this.successfulApiResponse(response, payload) };
		}
		if (this.apiKey) {
			return {
				kind: 'complete',
				response: this.failedApiResponse(response, payload, 'Request failed with API key authentication')
			};
		}
		if (allowAuthRetry && response.status === 401 && this.get_refresh_token()) {
			const refreshError = await this.refreshUnauthorizedRequest<T>();
			return refreshError ? { kind: 'complete', response: refreshError } : { kind: 'retry-after-refresh' };
		}
		return {
			kind: 'complete',
			response: this.failedApiResponse(response, payload, 'Unable to serve request')
		};
	}

	private async fetchWithRetry<T>(url: string, init: RequestInit = {}): Promise<ApiResponse<T>> {
		let allowAuthRetry = true;
		let timeoutRetryCount = 0;
		while (true) {
			try {
				const attempt = await this.fetchAttempt<T>(url, init, allowAuthRetry);
				if (attempt.kind === 'complete') {
					return attempt.response;
				}
				timeoutRetryCount = 0;
				allowAuthRetry = false;
			} catch (err: unknown) {
				if (this.shouldRetryTimeout(err, timeoutRetryCount)) {
					this.logTimeoutRetry(timeoutRetryCount);
					timeoutRetryCount += 1;
				} else {
					return this.requestError(err);
				}
			}
		}
	}

	private appendMultipartPayload(form: FormData, body: SerializableBody | undefined): void {
		if (body === undefined || body === null) {
			return;
		}
		if (!isPlainObject(body)) {
			form.append('payload', this.tryStringify(body));
			return;
		}
		for (const [key, value] of Object.entries(body)) {
			form.append(key, typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value));
		}
	}

	private appendMultipartFiles(form: FormData, files: maybeFile[]): void {
		for (const fileEntry of files) {
			if (Array.isArray(fileEntry)) {
				form.append(fileEntry[0], fileEntry[1]);
			} else {
				form.append('files', fileEntry);
			}
		}
	}

	private createMultipartBody(body: SerializableBody | undefined, files: maybeFile[]): FormData {
		const form = new FormData();
		this.appendMultipartPayload(form, body);
		this.appendMultipartFiles(form, files);
		return form;
	}

	private createRequestOptions(
		method: 'GET' | 'POST' | 'PUT' | 'DELETE',
		body: SerializableBody | undefined,
		files: maybeFile[] | undefined
	): RequestInit {
		const options: RequestInit = { method };
		if (files && files.length > 0) {
			options.body = this.createMultipartBody(body, files);
		} else if (body !== undefined) {
			options.body = this.tryStringify(body);
		}
		return options;
	}

	private debugRequestBody(body: BodyInit | null | undefined): unknown {
		if (typeof body !== 'string') {
			return sanitizeDebugValue(body);
		}
		try {
			return sanitizeDebugValue(JSON.parse(body) as unknown);
		} catch {
			return body;
		}
	}

	private logRequest(method: string, url: string, body: SerializableBody | undefined, options: RequestInit): void {
		if (!this.debug) {
			return;
		}
		console.log(
			`Making ${method} request to: ${url} (timeout: ${this.timeoutMs}ms, max retries: ${this.maxRetries})`
		);
		if (body !== undefined) {
			console.log('Request body:', this.debugRequestBody(options.body));
		}
	}

	/**
	 * Performs a generic HTTP request to the API
	 * @param {'GET'|'POST'|'PUT'|'DELETE'} method - The HTTP method to use
	 * @param {string} command - The API endpoint path
	 * @param {SerializableBody} [body] - Optional request body (for POST/PUT/DELETE requests)
	 * @returns {Promise<ApiResponse<T>>} A promise resolving to the API response
	 * @template T - The expected type of the response data
	 */
	async request<T>(
		method: 'GET' | 'POST' | 'PUT' | 'DELETE',
		command: string,
		body?: SerializableBody,
		files?: maybeFile[]
	): Promise<ApiResponse<T>> {
		const url = `${this.apiUrl}${command}`;
		let options: RequestInit;
		try {
			options = this.createRequestOptions(method, body, files);
		} catch (error) {
			return this.requestError(error);
		}
		this.logRequest(method, url, body, options);
		return this.fetchWithRetry<T>(url, options);
	}

	async get<T>(command: string): Promise<ApiResponse<T>> {
		return this.request<T>('GET', command);
	}

	async post<T>(command: string, body?: SerializableBody, files?: maybeFile[]): Promise<ApiResponse<T>> {
		return this.request<T>('POST', command, body, files);
	}

	async put<T>(command: string, body?: SerializableBody): Promise<ApiResponse<T>> {
		return this.request<T>('PUT', command, body);
	}

	async delete<T>(command: string, body?: SerializableBody): Promise<ApiResponse<T>> {
		return this.request<T>('DELETE', command, body);
	}

	async ping(): Promise<ApiResponse<ApiPingRes>> {
		const basePath = this.apiBasePath === '/' ? '' : this.apiBasePath.replace(/\/+$/, '');
		return this.get<ApiPingRes>(`${basePath}/v1/ping`);
	}

	async me<T = ApiMeRes>(): Promise<ApiResponse<T>> {
		return this.get<T>(`${this.authBasePath}/me`);
	}

	async sessions<T = ApiSessionsRes>(): Promise<ApiResponse<T>> {
		return this.get<T>(`${this.authBasePath}/me/sessions`);
	}

	async revokeSession<T = ApiRevokeSessionRes>(sessionId: string): Promise<ApiResponse<T>> {
		return this.delete<T>(`${this.authBasePath}/me/sessions/${encodeURIComponent(sessionId)}`);
	}
}

export default ApiClient;
