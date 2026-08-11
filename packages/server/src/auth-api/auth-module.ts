import { createHash, randomUUID } from 'node:crypto';

import { isoBase64URL } from '@simplewebauthn/server/helpers';

import { ApiError, type ApiCookieOptions, type ApiRequest, type ApiRoute, type ApiServer } from '../apicore-server.js';
import { buildAuthCookieOptions } from '../auth-cookie-options.js';
import { emptyObjectSchema } from '../base/json-schema.js';

import { BaseAuthModule, type AuthProviderModule } from './module.js';
import {
	loginBodySchema,
	refreshBodySchema,
	logoutBodySchema,
	passkeyChallengeBodySchema,
	passkeyVerifyBodySchema,
	passkeyCredentialParamsSchema,
	impersonateBodySchema,
	deleteImpersonationQuerySchema,
	oauthProviderParamsSchema,
	oauthStartBodySchema,
	oauthAuthorizeBodySchema,
	oauthTokenBodySchema,
	sessionParamsSchema
} from './schemas.js';
import { BaseAuthAdapter } from './storage.js';

import type {
	ApiLoginRes,
	ApiLogoutRes,
	ApiMeRes,
	ApiOAuthAuthorizeRes,
	ApiOAuthTokenRes,
	ApiPasskeyChallengeRes,
	ApiPasskeyCredential,
	ApiPasskeyDeleteRes,
	ApiPasskeyListRes,
	ApiPasskeyVerifyRes,
	ApiRefreshRes,
	ApiRevokeSessionRes,
	ApiSessionsRes,
	SessionInfo
} from '../common.js';
import type { AuthAdapter, AuthIdentifier } from './types.js';
import type {
	OAuthCallbackParams,
	OAuthCallbackResult,
	OAuthClient,
	OAuthStartParams,
	OAuthStartResult
} from '../oauth/types.js';
import type {
	PasskeyChallengeParams,
	PasskeyChallengeRecord,
	PasskeyVerificationParams,
	PasskeyVerificationResult
} from '../passkey/types.js';
import type { TokenPair, Token } from '../token/types.js';

interface CanImpersonateContext<UserEntity> {
	apiReq: ApiRequest;
	realUser: UserEntity;
	realUserId: AuthIdentifier;
	targetUser: UserEntity;
	effectiveUserId: AuthIdentifier;
}

type AuthRateLimitEndpoint = 'login' | 'passkey-challenge' | 'oauth-token' | 'oauth-authorize';
// Valid bcrypt cost-12 hash used to keep unknown-user password checks on the normal verification path.
const DUMMY_PASSWORD_HASH = '$2b$12$bklvrVeo9p8HMz2ubRyno.2eTMD7CGgI/mPP1Ruj8TyH4YabyR6MK';

interface AuthModuleOptions<UserEntity> {
	namespace?: string;
	defaultDomain?: string;
	canImpersonate?: (context: CanImpersonateContext<UserEntity>) => Promise<boolean> | boolean;
	rateLimit?: (context: { apiReq: ApiRequest; endpoint: AuthRateLimitEndpoint }) => Promise<void> | void;
	allowInsecurePkcePlain?: boolean;
}

interface LoginBody extends Record<string, unknown> {
	login?: string;
	password?: string;
	domain?: string;
	fingerprint?: string;
	label?: string;
	browser?: string;
	device?: string;
	ip?: string;
	os?: string;
	keepSession?: boolean | number | string;
}

interface RefreshBody extends Record<string, unknown> {
	refreshToken?: string;
	domain?: string;
	fingerprint?: string;
	label?: string;
	keepSession?: boolean | number | string;
}

interface LogoutBody extends Record<string, unknown> {
	token?: string;
}

interface ImpersonationMetadataBody extends Record<string, unknown> {
	keepSession?: unknown;
	domain?: unknown;
	fingerprint?: unknown;
	label?: unknown;
	browser?: unknown;
	device?: unknown;
	ip?: unknown;
	os?: unknown;
	clientId?: unknown;
	scope?: unknown;
	loginType?: unknown;
}

interface ImpersonateBody extends ImpersonationMetadataBody {
	userId?: unknown;
	login?: unknown;
}

interface PasskeyChallengeBody extends Record<string, unknown> {
	action?: unknown;
	login?: unknown;
	userId?: unknown;
}

interface PasskeyVerifyBody extends Record<string, unknown> {
	login?: unknown;
	userId?: unknown;
	expectedChallenge?: unknown;
	response?: unknown;
	userAgent?: unknown;
	domain?: unknown;
	fingerprint?: unknown;
	label?: unknown;
	browser?: unknown;
	device?: unknown;
	ip?: unknown;
	os?: unknown;
	keepSession?: unknown;
}

interface OAuthStartBody extends Record<string, unknown> {
	redirectUri?: unknown;
	scope?: unknown;
	state?: unknown;
	extras?: unknown;
}

interface OAuthAuthorizeBody extends Record<string, unknown> {
	clientId?: unknown;
	redirectUri?: unknown;
	scope?: unknown;
	state?: unknown;
	codeChallenge?: unknown;
	codeChallengeMethod?: unknown;
	login?: unknown;
	password?: unknown;
	refreshToken?: unknown;
}

interface OAuthTokenBody extends Record<string, unknown> {
	grant_type?: unknown;
	code?: unknown;
	redirect_uri?: unknown;
	code_verifier?: unknown;
	refresh_token?: unknown;
	client_id?: unknown;
	client_secret?: unknown;
}

type TokenMetadata = Partial<Token> & { sessionCookie?: boolean };
type TokenMetadataInput = Pick<
	ImpersonationMetadataBody,
	'domain' | 'fingerprint' | 'label' | 'browser' | 'device' | 'ip' | 'os'
>;

interface TokenIssueOptions extends TokenMetadata {
	expires?: Date;
	sessionCookie?: boolean;
}

interface NormalizedTokenMetadata extends TokenMetadata {
	domain: string;
	fingerprint: string;
	label: string;
	browser: string;
	device: string;
	ip: string;
	os: string;
}

type TokenClaims = TokenMetadata & {
	uid: string;
	exp?: number;
	iat?: number;
};

type AuthCapableServer<PublicUser> = ApiServer & {
	initiateOAuth?: (params: OAuthStartParams) => Promise<OAuthStartResult>;
	completeOAuth?: (params: OAuthCallbackParams) => Promise<OAuthCallbackResult<PublicUser>>;
};

type PasskeyStorageHints = {
	passkeyService?: unknown;
	passkeyStore?: unknown;
	adapter?: { passkeyService?: unknown; passkeyStore?: unknown };
};

type OAuthStorageHints = {
	oauthStore?: unknown;
	adapter?: { oauthStore?: unknown };
};

function isAuthIdentifier(value: unknown): value is AuthIdentifier {
	if (typeof value === 'string') return value.length > 0;
	if (typeof value === 'number') return Number.isFinite(value);
	return false;
}

function toStringOrNull(value: unknown): string | null {
	if (typeof value === 'string') {
		const trimmed = value.trim();
		return trimmed.length > 0 ? trimmed : null;
	}
	return null;
}

function toScopeArray(scope: unknown): string[] | undefined {
	if (typeof scope === 'string') {
		return scope.split(/\s+/).filter((entry) => entry.length > 0);
	}
	if (Array.isArray(scope) && scope.every((entry) => typeof entry === 'string')) {
		return scope.filter((entry) => entry.length > 0) as string[];
	}
	return undefined;
}

function base64UrlEncode(buffer: Buffer): string {
	return buffer.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function sha256Base64Url(value: string): string {
	const hash = createHash('sha256').update(value).digest();
	return base64UrlEncode(hash);
}

export default class AuthModule<UserEntity, PublicUser>
	extends BaseAuthModule<UserEntity>
	implements AuthProviderModule<UserEntity>
{
	public static override defaultNamespace = '/auth';

	public override get server(): AuthCapableServer<PublicUser> {
		return super.server as AuthCapableServer<PublicUser>;
	}

	public override set server(value: AuthCapableServer<PublicUser>) {
		super.server = value;
	}

	private readonly defaultDomain?: string;
	private readonly canImpersonateHook?: (context: CanImpersonateContext<UserEntity>) => Promise<boolean> | boolean;
	private readonly rateLimitHook?: AuthModuleOptions<UserEntity>['rateLimit'];
	private readonly allowInsecurePkcePlain: boolean;

	constructor(options: AuthModuleOptions<UserEntity> = {}) {
		super({ namespace: options.namespace ?? AuthModule.defaultNamespace });
		this.defaultDomain = options.defaultDomain;
		this.canImpersonateHook = options.canImpersonate;
		this.rateLimitHook = options.rateLimit;
		this.allowInsecurePkcePlain = options.allowInsecurePkcePlain ?? false;
	}

	protected get storage(): AuthAdapter<UserEntity, PublicUser> {
		return this.server.getAuthStorage() as AuthAdapter<UserEntity, PublicUser>;
	}

	protected async canImpersonate(apiReq: ApiRequest, realUser: UserEntity, targetUser: UserEntity): Promise<boolean> {
		const realUserId = this.storage.getUserId(realUser);
		const effectiveUserId = this.storage.getUserId(targetUser);
		if (this.canImpersonateHook) {
			const allowed = await this.canImpersonateHook({
				apiReq,
				realUser,
				realUserId,
				targetUser,
				effectiveUserId
			});
			if (allowed === true) return true;
			if (allowed === false) return false;
		}
		const storageWithHook = this.storage as AuthAdapter<UserEntity, PublicUser> & {
			canImpersonate?: (params: {
				realUserId: AuthIdentifier;
				effectiveUserId: AuthIdentifier;
			}) => Promise<boolean>;
		};
		if (typeof storageWithHook.canImpersonate === 'function') {
			const allowed = await storageWithHook.canImpersonate({
				realUserId,
				effectiveUserId
			});
			return !!allowed;
		}
		return String(realUserId) === String(effectiveUserId);
	}

	protected async ensureImpersonationAllowed(
		apiReq: ApiRequest,
		realUser: UserEntity,
		targetUser: UserEntity
	): Promise<void> {
		const permitted = await this.canImpersonate(apiReq, realUser, targetUser);
		if (!permitted) {
			throw new ApiError({
				code: 403,
				message: 'Impersonation is not permitted'
			});
		}
	}

	protected buildTokenPayload(user: UserEntity, metadata: TokenMetadata = {}): TokenClaims {
		return {
			...metadata,
			uid: String(this.storage.getUserId(user))
		};
	}

	protected buildTokenMetadata(metadata: TokenMetadata = {}): NormalizedTokenMetadata {
		const scope = metadata.scope;
		const domain = metadata.domain ?? this.defaultDomain ?? '';
		let fingerprint = metadata.fingerprint ?? metadata.clientId ?? '';
		if (typeof fingerprint === 'string') {
			fingerprint = fingerprint.trim();
		} else {
			fingerprint = '';
		}
		// Avoid every client sharing the empty-string fingerprint which collapses sessions into one bucket.
		if (!fingerprint) {
			fingerprint = `srv-${randomUUID()}`;
		}
		return {
			domain,
			fingerprint,
			label: metadata.label ?? (Array.isArray(scope) ? scope.join(' ') : typeof scope === 'string' ? scope : ''),
			clientId: metadata.clientId,
			ruid: metadata.ruid,
			scope: metadata.scope,
			browser: metadata.browser ?? '',
			device: metadata.device ?? '',
			ip: metadata.ip ?? '',
			os: metadata.os ?? '',
			refreshTtlSeconds: this.normalizeRefreshTtlSeconds(metadata.refreshTtlSeconds),
			sessionCookie: typeof metadata.sessionCookie === 'boolean' ? metadata.sessionCookie : undefined,
			loginType: metadata.loginType,
			sessionId: metadata.sessionId
		};
	}

	protected enrichTokenMetadata(apiReq: ApiRequest, metadata: TokenMetadata = {}): TokenMetadata {
		const enriched: TokenMetadata = { ...metadata };
		const clientInfo = apiReq.getClientInfo();
		if (!enriched.ip && clientInfo.ip) {
			enriched.ip = clientInfo.ip;
		}
		if (!enriched.browser && clientInfo.browser) {
			enriched.browser = clientInfo.browser;
		}
		if (!enriched.os && clientInfo.os) {
			enriched.os = clientInfo.os;
		}
		if (!enriched.device && clientInfo.device) {
			enriched.device = clientInfo.device;
		}

		return enriched;
	}

	private sessionRefreshTtlSeconds(): number {
		return Math.max(1, this.server.config.sessionRefreshExpiry ?? 24 * 60 * 60);
	}

	private normalizeRefreshTtlSeconds(value: unknown): number | undefined {
		if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
			return Math.floor(value);
		}
		if (typeof value === 'string') {
			const trimmed = value.trim();
			if (!trimmed) {
				return undefined;
			}
			const parsed = Number(trimmed);
			if (Number.isFinite(parsed) && parsed > 0) {
				return Math.floor(parsed);
			}
		}
		return undefined;
	}

	private resolveSessionPreferences(
		candidate: unknown
	): Pick<TokenIssueOptions, 'refreshTtlSeconds' | 'sessionCookie'> {
		if (candidate === undefined || candidate === null) {
			return {};
		}
		if (typeof candidate === 'boolean') {
			return candidate
				? {}
				: {
						sessionCookie: true,
						refreshTtlSeconds: this.sessionRefreshTtlSeconds()
					};
		}
		if (typeof candidate === 'number') {
			if (candidate === 0) {
				return {
					sessionCookie: true,
					refreshTtlSeconds: this.sessionRefreshTtlSeconds()
				};
			}
			const ttl = this.normalizeRefreshTtlSeconds(candidate);
			return ttl ? { sessionCookie: false, refreshTtlSeconds: ttl } : {};
		}
		if (typeof candidate === 'string') {
			const trimmed = candidate.trim();
			if (!trimmed) {
				return {};
			}
			if (/^(true|yes|1)$/i.test(trimmed)) {
				return {};
			}
			if (/^(false|no|0)$/i.test(trimmed)) {
				return {
					sessionCookie: true,
					refreshTtlSeconds: this.sessionRefreshTtlSeconds()
				};
			}
			const ttl = this.normalizeRefreshTtlSeconds(trimmed);
			return ttl ? { sessionCookie: false, refreshTtlSeconds: ttl } : {};
		}
		return {};
	}

	private mergeSessionPreferences(
		...prefs: Array<Pick<TokenIssueOptions, 'refreshTtlSeconds' | 'sessionCookie'> | undefined>
	): Pick<TokenIssueOptions, 'refreshTtlSeconds' | 'sessionCookie'> {
		const merged: Pick<TokenIssueOptions, 'refreshTtlSeconds' | 'sessionCookie'> = {};
		for (const pref of prefs) {
			if (!pref) {
				continue;
			}
			if (merged.sessionCookie === undefined && pref.sessionCookie !== undefined) {
				merged.sessionCookie = pref.sessionCookie;
			}
			if (merged.refreshTtlSeconds === undefined && typeof pref.refreshTtlSeconds === 'number') {
				merged.refreshTtlSeconds = pref.refreshTtlSeconds;
			}
		}
		return merged;
	}

	private sessionPrefsFromRecord(
		record: Record<string, unknown> | null | undefined
	): Pick<TokenIssueOptions, 'refreshTtlSeconds' | 'sessionCookie'> {
		if (!record) {
			return {};
		}
		const carrier = record as {
			refreshTtlSeconds?: unknown;
			sessionCookie?: unknown;
		};
		const prefs: Pick<TokenIssueOptions, 'refreshTtlSeconds' | 'sessionCookie'> = {};
		if (typeof carrier.sessionCookie === 'boolean') {
			prefs.sessionCookie = carrier.sessionCookie;
		}
		const ttl = this.normalizeRefreshTtlSeconds(carrier.refreshTtlSeconds);
		if (ttl !== undefined) {
			prefs.refreshTtlSeconds = ttl;
		}
		return prefs;
	}

	private validateCredentialId(apiReq: ApiRequest): string {
		const paramId = toStringOrNull(apiReq.req.params?.credentialId);
		const bodyId = toStringOrNull((apiReq.req.body as Record<string, unknown>)?.credentialId);
		const credentialId = paramId ?? bodyId;
		if (!credentialId) {
			throw new ApiError({
				code: 400,
				message: 'credentialId is required'
			});
		}
		try {
			isoBase64URL.toBuffer(credentialId);
		} catch {
			throw new ApiError({ code: 400, message: 'Invalid credentialId' });
		}
		return credentialId;
	}

	private normalizeCredentialId(value: Buffer | string): Buffer {
		if (Buffer.isBuffer(value)) {
			return value;
		}
		try {
			return Buffer.from(isoBase64URL.toBuffer(value));
		} catch {
			try {
				return Buffer.from(value, 'base64');
			} catch {
				return Buffer.from(value);
			}
		}
	}

	private toIsoDate(value: Date | string | undefined): string | undefined {
		if (!value) {
			return undefined;
		}
		const date = value instanceof Date ? value : new Date(value);
		return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
	}

	private cookieOptions(apiReq: ApiRequest): ApiCookieOptions {
		return buildAuthCookieOptions(this.server.config, apiReq.req);
	}

	private setJwtCookies(
		apiReq: ApiRequest,
		tokens: { accessToken?: string | null; refreshToken?: string | null },
		preferences: {
			sessionCookie?: boolean;
			refreshTtlSeconds?: number;
		} = {}
	): void {
		const conf = this.server.config;
		const options = this.cookieOptions(apiReq);
		const sessionCookie = preferences.sessionCookie ?? false;
		const accessMaxAge = Math.max(1, conf.accessExpiry) * 1000;
		const refreshSeconds = Math.max(1, preferences.refreshTtlSeconds ?? conf.refreshExpiry);
		const refreshMaxAge = refreshSeconds * 1000;

		// When sessionCookie is true we omit maxAge so the browser deletes the
		// cookie on close.  The server-side JWT still has its own expiry, which
		// limits exposure if the browser crashes without running its cleanup.
		const accessOptions = sessionCookie ? options : { ...options, maxAge: accessMaxAge };
		const refreshOptions = sessionCookie ? options : { ...options, maxAge: refreshMaxAge };

		if (tokens.accessToken) {
			apiReq.res.cookie(conf.accessCookie, tokens.accessToken, accessOptions);
		} else {
			apiReq.res.clearCookie(conf.accessCookie, options);
		}

		if (tokens.refreshToken) {
			apiReq.res.cookie(conf.refreshCookie, tokens.refreshToken, refreshOptions);
		} else {
			apiReq.res.clearCookie(conf.refreshCookie, options);
		}
	}

	public async issueTokens(
		apiReq: ApiRequest,
		user: UserEntity,
		metadata: TokenIssueOptions = {}
	): Promise<TokenPair> {
		const conf = this.server.config;
		const enrichedMetadata = this.enrichTokenMetadata(apiReq, {
			...metadata,
			sessionId: metadata.sessionId ?? randomUUID()
		});
		const payload = {
			...this.buildTokenPayload(user, enrichedMetadata),
			jti: randomUUID()
		};

		const access = this.server.jwtSign(payload, conf.accessSecret, conf.accessExpiry);
		if (!access.success || !access.token) {
			throw new ApiError({
				code: 500,
				message: access.error ?? 'Unable to sign access token'
			});
		}

		const meta = this.buildTokenMetadata(enrichedMetadata);
		const wantsSessionCookie = meta.sessionCookie === true;
		const customRefreshTtl = typeof meta.refreshTtlSeconds === 'number' ? meta.refreshTtlSeconds : undefined;
		const sessionRefreshTtl = this.sessionRefreshTtlSeconds();
		const defaultRefreshTtl = Math.max(1, conf.refreshExpiry);
		const refreshLifetimeSeconds = wantsSessionCookie
			? Math.max(1, customRefreshTtl ?? sessionRefreshTtl)
			: Math.max(1, customRefreshTtl ?? defaultRefreshTtl);
		const storedRefreshTtlSeconds = wantsSessionCookie
			? Math.max(1, customRefreshTtl ?? sessionRefreshTtl)
			: customRefreshTtl;
		meta.refreshTtlSeconds =
			typeof storedRefreshTtlSeconds === 'number' && storedRefreshTtlSeconds > 0
				? storedRefreshTtlSeconds
				: undefined;
		meta.sessionCookie = wantsSessionCookie;

		const refresh = this.server.jwtSign(payload, conf.refreshSecret, refreshLifetimeSeconds);
		if (!refresh.success || !refresh.token) {
			throw new ApiError({
				code: 500,
				message: refresh.error ?? 'Unable to sign refresh token'
			});
		}

		const expiresAt = metadata.expires ?? new Date(Date.now() + refreshLifetimeSeconds * 1000);
		const issuedAt = new Date();
		const lastSeenAt = issuedAt;
		await this.server.storeToken({
			accessToken: access.token,
			refreshToken: refresh.token,
			sessionId: meta.sessionId,
			userId: payload.uid,
			ruid: meta.ruid,
			domain: meta.domain,
			fingerprint: meta.fingerprint,
			label: meta.label,
			browser: meta.browser,
			device: meta.device,
			ip: meta.ip,
			os: meta.os,
			clientId: meta.clientId,
			scope: meta.scope,
			loginType: meta.loginType,
			refreshTtlSeconds: meta.refreshTtlSeconds,
			sessionCookie: meta.sessionCookie,
			expires: expiresAt,
			issuedAt,
			lastSeenAt
		});

		this.setJwtCookies(
			apiReq,
			{
				accessToken: access.token,
				refreshToken: refresh.token
			},
			{
				sessionCookie: wantsSessionCookie,
				refreshTtlSeconds: refreshLifetimeSeconds
			}
		);

		return {
			accessToken: access.token,
			refreshToken: refresh.token
		};
	}

	private assertAuthReady(): void {
		const conf = this.server.config;
		if (!conf.accessSecret || !conf.refreshSecret) {
			throw new ApiError({
				code: 500,
				message: 'Auth secrets are not configured'
			});
		}
	}

	private parseLoginBody(apiReq: ApiRequest): Required<Pick<LoginBody, 'login' | 'password'>> & TokenIssueOptions {
		const body = (apiReq.req.body ?? {}) as LoginBody;
		// login and password are guaranteed present and non-empty by JSON Schema
		const login = body.login as string;
		const password = body.password as string;
		const sessionPrefs = this.resolveSessionPreferences(body.keepSession);

		return {
			login,
			password,
			...this.metadataFromBody(body),
			loginType: 'credentials',
			...sessionPrefs
		};
	}

	private parseImpersonationRequest(apiReq: ApiRequest): {
		targetIdentifier: AuthIdentifier;
		metadata: TokenIssueOptions;
	} {
		const body = (apiReq.req.body ?? {}) as ImpersonateBody;
		const targetIdentifier = this.resolveImpersonationIdentifier(body);
		const metadata = this.buildImpersonationMetadata(body);
		return { targetIdentifier, metadata };
	}

	private resolveImpersonationIdentifier(body: ImpersonateBody): AuthIdentifier {
		if (isAuthIdentifier(body.userId)) {
			return body.userId;
		}
		const login = toStringOrNull(body.login);
		if (login) {
			return login as AuthIdentifier;
		}
		throw new ApiError({
			code: 400,
			message: 'userId or login is required'
		});
	}

	private buildImpersonationMetadata(body: ImpersonationMetadataBody): TokenIssueOptions {
		const sessionPrefs = this.resolveSessionPreferences(body.keepSession);
		return {
			...this.metadataFromBody(body),
			clientId: toStringOrNull(body.clientId) ?? undefined,
			scope: toScopeArray(body.scope),
			loginType: toStringOrNull(body.loginType) ?? undefined,
			...sessionPrefs
		};
	}

	private metadataFromBody(body: TokenMetadataInput): TokenIssueOptions {
		return {
			domain: toStringOrNull(body.domain) ?? undefined,
			fingerprint: toStringOrNull(body.fingerprint) ?? undefined,
			label: toStringOrNull(body.label) ?? undefined,
			browser: toStringOrNull(body.browser) ?? undefined,
			device: toStringOrNull(body.device) ?? undefined,
			ip: toStringOrNull(body.ip) ?? undefined,
			os: toStringOrNull(body.os) ?? undefined
		};
	}

	private async getUserOrThrow(identifier: AuthIdentifier, errorMessage: string): Promise<UserEntity> {
		const user = await this.storage.getUser(identifier);
		if (!user) {
			throw new ApiError({ code: 403, message: errorMessage });
		}
		return user as UserEntity;
	}

	private async verifyCredentials(login: string, password: string): Promise<UserEntity | null> {
		const user = await this.storage.getUser(login);
		const hash = user ? this.storage.getUserPasswordHash(user as UserEntity) : '';
		const candidateHash = hash || DUMMY_PASSWORD_HASH;
		const verified = await this.storage.verifyPassword(password, candidateHash);
		return user && hash && verified ? (user as UserEntity) : null;
	}

	private getRealUserIdentifier(apiReq: ApiRequest): AuthIdentifier {
		const candidate =
			typeof apiReq.getRealUid === 'function'
				? apiReq.getRealUid()
				: ((apiReq as ApiRequest & { realUid?: AuthIdentifier | null }).realUid ?? null);
		if (!isAuthIdentifier(candidate)) {
			throw new ApiError({
				code: 401,
				message: 'Authentication required'
			});
		}
		return candidate;
	}

	private async resolveActorContext(apiReq: ApiRequest): Promise<{ user: UserEntity; userId: AuthIdentifier }> {
		const realIdentifier = this.getRealUserIdentifier(apiReq);
		const user = await this.getUserOrThrow(realIdentifier, 'Authenticated user not found');
		return { user, userId: this.storage.getUserId(user) };
	}

	private authIdentifiersMatch(left: AuthIdentifier, right: AuthIdentifier): boolean {
		return String(left) === String(right);
	}

	private getPasskeyRequestedIdentifier(body: PasskeyChallengeBody | PasskeyVerifyBody): AuthIdentifier | null {
		if (isAuthIdentifier(body.userId)) {
			return body.userId as AuthIdentifier;
		}
		const login = toStringOrNull(body.login);
		return login ?? null;
	}

	private async requirePasskeyRegistrationActor(
		apiReq: ApiRequest,
		targetUserId?: AuthIdentifier
	): Promise<{ user: UserEntity; userId: AuthIdentifier }> {
		if (!apiReq.tokenData) {
			await this.server.authenticateRequest(apiReq, 'maybe');
		}
		if (!apiReq.tokenData) {
			throw new ApiError({
				code: 401,
				message: 'Passkey registration requires authentication'
			});
		}
		if (apiReq.isImpersonating()) {
			throw new ApiError({
				code: 403,
				message: 'Passkey registration is not allowed while impersonating'
			});
		}
		const actor = await this.resolveActorContext(apiReq);
		if (targetUserId !== undefined && !this.authIdentifiersMatch(actor.userId, targetUserId)) {
			throw new ApiError({
				code: 403,
				message: 'Passkey registration is only allowed for the authenticated user'
			});
		}
		return actor;
	}

	private async resolvePasskeyRegistrationTargetUserId(
		record: PasskeyChallengeRecord
	): Promise<AuthIdentifier | undefined> {
		if (record.userId !== undefined) {
			return record.userId;
		}
		if (record.login) {
			const user = await this.getUserOrThrow(
				record.login,
				'Passkey registration is only allowed for the authenticated user'
			);
			return this.storage.getUserId(user);
		}
		return undefined;
	}

	private async preauthorizePasskeyRegistrationVerification(
		apiReq: ApiRequest,
		expectedChallenge: string
	): Promise<void> {
		const getPasskeyChallenge = this.storage.getPasskeyChallenge;
		if (!this.storageImplements('getPasskeyChallenge') || typeof getPasskeyChallenge !== 'function') {
			throw new ApiError({
				code: 501,
				message: 'Passkey challenge lookup is required for secure verification'
			});
		}
		const challengeRecord = await getPasskeyChallenge.call(this.storage, expectedChallenge);
		if (!challengeRecord || challengeRecord.action !== 'register') {
			return;
		}
		const targetUserId = await this.resolvePasskeyRegistrationTargetUserId(challengeRecord);
		await this.requirePasskeyRegistrationActor(apiReq, targetUserId);
	}

	/**
	 * Final actor check for a completed registration.
	 *
	 * Challenge lookup authorizes the recorded target before verification. Repeat
	 * the check against the verified user and roll back on rejection as defense in
	 * depth against challenge-store races or an inconsistent adapter result.
	 */
	private async authorizeCompletedPasskeyRegistration(
		apiReq: ApiRequest,
		user: UserEntity,
		result: PasskeyVerificationResult
	): Promise<void> {
		try {
			await this.requirePasskeyRegistrationActor(apiReq, this.storage.getUserId(user));
		} catch (error) {
			await this.rollbackPasskeyRegistration(result);
			throw error;
		}
	}

	private async rollbackPasskeyRegistration(result: PasskeyVerificationResult): Promise<void> {
		const credentialId = toStringOrNull(result.credentialId);
		if (!credentialId || typeof this.storage.deletePasskeyCredential !== 'function') {
			return;
		}
		try {
			await this.storage.deletePasskeyCredential(this.normalizeCredentialId(credentialId));
		} catch (error) {
			console.error('[apicore] Failed to roll back an unauthorized passkey registration', error);
		}
	}

	private extractRefreshToken(
		apiReq: ApiRequest,
		body: RefreshBody | LogoutBody | Record<string, unknown>
	): string | null {
		const conf = this.server.config;
		if (typeof body.refreshToken === 'string') {
			return body.refreshToken;
		}
		const logoutBody = body as LogoutBody;
		if (typeof logoutBody.token === 'string') {
			return logoutBody.token;
		}
		const fromCookie = apiReq.req.cookies?.[conf.refreshCookie];
		return typeof fromCookie === 'string' && fromCookie.length > 0 ? fromCookie : null;
	}

	private verifyRefreshTokenOrThrow(refreshToken: string): TokenClaims {
		const verify = this.server.jwtVerify<TokenClaims>(refreshToken, this.server.config.refreshSecret);
		if (!verify.success || !verify.data) {
			const expired = 'expired' in verify && (verify as { expired?: boolean }).expired;
			throw new ApiError({
				code: expired ? 403 : 401,
				message: verify.error ?? 'Unable to verify refresh token'
			});
		}
		return verify.data;
	}

	private normalizeScope(scope: unknown): string | string[] | undefined {
		if (typeof scope === 'string') {
			return scope;
		}
		if (Array.isArray(scope) && scope.every((entry) => typeof entry === 'string')) {
			return scope as string[];
		}
		return undefined;
	}

	private resolveAuthorizePkce(input: OAuthAuthorizeBody): {
		codeChallenge?: string;
		codeChallengeMethod?: 'plain' | 'S256';
	} {
		const codeChallenge = toStringOrNull(input.codeChallenge) ?? undefined;
		const codeChallengeMethod = toStringOrNull(input.codeChallengeMethod) ?? undefined;
		if (codeChallenge && !codeChallengeMethod) {
			throw new ApiError({
				code: 400,
				message: 'codeChallengeMethod is required when codeChallenge is provided'
			});
		}
		if (!codeChallenge && codeChallengeMethod) {
			throw new ApiError({
				code: 400,
				message: 'codeChallenge is required when codeChallengeMethod is provided'
			});
		}
		const resolvedCodeChallengeMethod = this.resolvePkceChallengeMethod(codeChallengeMethod);
		if (codeChallengeMethod && !resolvedCodeChallengeMethod) {
			throw new ApiError({
				code: 400,
				message: 'Invalid codeChallengeMethod'
			});
		}
		return {
			codeChallenge,
			codeChallengeMethod: resolvedCodeChallengeMethod
		};
	}

	private async postLogin(apiReq: ApiRequest): Promise<[number, ApiLoginRes<PublicUser>]> {
		await this.applyRateLimit(apiReq, 'login');
		this.assertAuthReady();

		const { login, password, ...metadata } = this.parseLoginBody(apiReq);
		const user = await this.verifyCredentials(login, password);
		if (!user) {
			throw new ApiError({
				code: 400,
				message: 'Invalid credentials'
			});
		}

		const pair = await this.issueTokens(apiReq, user, metadata);
		const publicUser = this.storage.filterUser(user) as unknown as PublicUser;
		return [200, { ...pair, user: publicUser }];
	}

	private async postRefresh(apiReq: ApiRequest): Promise<[number, ApiRefreshRes]> {
		this.assertAuthReady();
		const body = (apiReq.req.body ?? {}) as RefreshBody;
		const sessionPrefs = this.resolveSessionPreferences(body.keepSession);
		const providedToken = this.extractRefreshToken(apiReq, body);
		if (!providedToken) {
			throw new ApiError({ code: 401, message: 'Missing refresh token' });
		}

		const stored = await this.server.getToken({
			refreshToken: providedToken
		});
		if (!stored) {
			throw new ApiError({ code: 401, message: 'Invalid refresh token' });
		}

		const claims = this.verifyRefreshTokenOrThrow(providedToken);

		// Delete the token immediately after verification to narrow the TOCTOU window.
		// This must happen before the slower getUserOrThrow call.
		const deleted = await this.server.deleteToken({
			refreshToken: providedToken
		});
		if (deleted === 0) {
			// Another concurrent request already consumed this refresh token.
			throw new ApiError({ code: 401, message: 'Invalid refresh token' });
		}

		const metadata: TokenIssueOptions = {
			domain: stored.domain,
			fingerprint: stored.fingerprint,
			label: stored.label,
			clientId: stored.clientId,
			scope: stored.scope,
			browser: stored.browser,
			device: stored.device,
			ip: stored.ip,
			os: stored.os,
			loginType: stored.loginType,
			sessionId: stored.sessionId,
			ruid: stored.ruid ?? claims.ruid,
			refreshTtlSeconds: sessionPrefs.refreshTtlSeconds ?? stored.refreshTtlSeconds,
			sessionCookie: sessionPrefs.sessionCookie ?? stored.sessionCookie
		};
		const user = await this.getUserOrThrow(stored.userId ?? claims.uid, 'User not found');
		const pair = await this.issueTokens(apiReq, user, metadata);
		return [200, pair];
	}

	private async postLogout(apiReq: ApiRequest): Promise<[number, ApiLogoutRes]> {
		const body = (apiReq.req.body ?? {}) as LogoutBody;
		const refreshToken = this.extractRefreshToken(apiReq, body);
		if (!refreshToken) {
			throw new ApiError({ code: 401, message: 'Not logged in' });
		}

		this.setJwtCookies(apiReq, { accessToken: null, refreshToken: null });
		const revoked = await this.server.deleteToken({ refreshToken });
		return [200, { revoked }];
	}

	private toSessionInfo(record: Token, currentSessionId: string | undefined): SessionInfo | null {
		if (typeof record.sessionId !== 'string' || record.sessionId.length === 0) {
			return null;
		}
		const tokenHint = record.refreshToken ? `...${record.refreshToken.slice(-6)}` : undefined;
		return {
			sessionId: record.sessionId,
			current: record.sessionId === currentSessionId,
			tokenHint,
			expires: this.toIsoDate(record.expires),
			issuedAt: this.toIsoDate(record.issuedAt),
			lastSeenAt: this.toIsoDate(record.lastSeenAt),
			status: record.status,
			clientId: record.clientId,
			domain: record.domain,
			fingerprint: record.fingerprint,
			label: record.label,
			browser: record.browser,
			device: record.device,
			ip: record.ip,
			os: record.os,
			scope: record.scope ? [...record.scope] : undefined,
			loginType: record.loginType,
			sessionCookie: record.sessionCookie
		};
	}

	private async getSessions(apiReq: ApiRequest): Promise<[number, ApiSessionsRes]> {
		const uid = apiReq.tokenData?.uid;
		if (!isAuthIdentifier(uid)) {
			throw new ApiError({ code: 401, message: 'Not authenticated' });
		}
		const sessions = await this.server.listTokens(uid);
		const currentSessionId = apiReq.authToken?.sessionId ?? apiReq.tokenData?.sessionId;
		return [
			200,
			{
				sessions: sessions
					.map((record) => this.toSessionInfo(record, currentSessionId))
					.filter((session): session is SessionInfo => session !== null)
			}
		];
	}

	private async deleteSession(apiReq: ApiRequest): Promise<[number, ApiRevokeSessionRes]> {
		const uid = apiReq.tokenData?.uid;
		if (!isAuthIdentifier(uid)) {
			throw new ApiError({ code: 401, message: 'Not authenticated' });
		}
		const params = (apiReq.req.params ?? {}) as Record<string, unknown>;
		const sessionId = toStringOrNull(params.sessionId);
		if (!sessionId) {
			throw new ApiError({ code: 400, message: 'sessionId is required' });
		}
		const revoked = await this.server.deleteToken({
			sessionId,
			userId: String(uid)
		});
		const currentSessionId = apiReq.authToken?.sessionId ?? apiReq.tokenData?.sessionId;
		if (currentSessionId === sessionId) {
			this.setJwtCookies(apiReq, {
				accessToken: null,
				refreshToken: null
			});
		}
		return [200, { revoked }];
	}

	private async getMe(apiReq: ApiRequest): Promise<[number, ApiMeRes<PublicUser>]> {
		const uid = apiReq.tokenData?.uid;
		if (!isAuthIdentifier(uid)) {
			throw new ApiError({ code: 401, message: 'Not authenticated' });
		}
		const user = await this.getUserOrThrow(uid, 'User not found');
		return [200, await this.buildIdentityResponse(user, apiReq.getRealUid())];
	}

	private async buildIdentityResponse(
		user: UserEntity,
		realUserId: AuthIdentifier | null | undefined
	): Promise<ApiMeRes<PublicUser>> {
		const publicUser = this.storage.filterUser(user) as unknown as PublicUser;
		const effectiveId = String(this.storage.getUserId(user));
		const normalizedRealId =
			realUserId === undefined || realUserId === null ? null : String(realUserId).trim() || null;
		if (normalizedRealId === null || normalizedRealId === effectiveId) {
			return { user: publicUser };
		}

		const realUser = await this.getUserOrThrow(normalizedRealId, 'Real user not found');
		return {
			user: publicUser,
			ruser: this.storage.filterUser(realUser) as unknown as PublicUser
		};
	}

	private async postPasskeyChallenge(apiReq: ApiRequest): Promise<[number, ApiPasskeyChallengeRes]> {
		await this.applyRateLimit(apiReq, 'passkey-challenge');
		if (typeof this.storage.createPasskeyChallenge !== 'function') {
			throw new ApiError({
				code: 501,
				message: 'Passkey support is not configured'
			});
		}
		const body = (apiReq.req.body ?? {}) as PasskeyChallengeBody;
		// action is guaranteed to be 'register' | 'authenticate' by JSON Schema
		const action = body.action as string;

		const params: PasskeyChallengeParams = {
			action: action as 'register' | 'authenticate',
			login: toStringOrNull(body.login) ?? undefined,
			userId: isAuthIdentifier(body.userId) ? (body.userId as AuthIdentifier) : undefined
		};

		if (params.action === 'register') {
			const requestedIdentifier = this.getPasskeyRequestedIdentifier(body);
			if (requestedIdentifier !== null) {
				const targetUser = await this.getUserOrThrow(
					requestedIdentifier,
					'Passkey registration is only allowed for the authenticated user'
				);
				await this.requirePasskeyRegistrationActor(apiReq, this.storage.getUserId(targetUser));
			} else {
				await this.requirePasskeyRegistrationActor(apiReq);
			}
			const actor = await this.resolveActorContext(apiReq);
			params.userId = actor.userId;
			delete params.login;
		}

		const challenge = await this.storage.createPasskeyChallenge(params);
		return [200, challenge];
	}

	private async postPasskeyVerify(apiReq: ApiRequest): Promise<[number, ApiPasskeyVerifyRes<PublicUser>]> {
		if (typeof this.storage.verifyPasskeyResponse !== 'function') {
			throw new ApiError({
				code: 501,
				message: 'Passkey support is not configured'
			});
		}
		const body = (apiReq.req.body ?? {}) as PasskeyVerifyBody;
		const sessionPrefs = this.resolveSessionPreferences(body.keepSession);

		// expectedChallenge (string) and response (object) are guaranteed by JSON Schema
		const expectedChallenge = body.expectedChallenge as string;
		const response = body.response;

		const rawMetadata = this.metadataFromBody(body);
		const clientInfo = apiReq.getClientInfo();
		const userAgent = toStringOrNull(body.userAgent) ?? (clientInfo.ua ? clientInfo.ua : null);
		const requestMetadata = this.enrichTokenMetadata(apiReq, rawMetadata);

		const params: PasskeyVerificationParams = {
			expectedChallenge,
			response: response as Record<string, unknown>,
			login: toStringOrNull(body.login) ?? undefined,
			userId: isAuthIdentifier(body.userId) ? (body.userId as AuthIdentifier) : undefined,
			userAgent: userAgent ?? undefined,
			...requestMetadata,
			...sessionPrefs
		};

		await this.preauthorizePasskeyRegistrationVerification(apiReq, expectedChallenge);
		const result = await this.storage.verifyPasskeyResponse(params);
		if (!result.verified) {
			throw new ApiError({
				code: 401,
				message: 'Passkey verification failed'
			});
		}

		const user = await this.getUserFromPasskey(result, params);
		if (result.action === 'register') {
			await this.authorizeCompletedPasskeyRegistration(apiReq, user, result);
		}

		if (result.tokens?.accessToken && result.tokens.refreshToken) {
			const storagePrefs = this.sessionPrefsFromRecord(result as Record<string, unknown>);
			const cookiePrefs = this.mergeSessionPreferences(sessionPrefs, storagePrefs);
			const refreshTtlForCookie = cookiePrefs.sessionCookie
				? (cookiePrefs.refreshTtlSeconds ?? this.sessionRefreshTtlSeconds())
				: cookiePrefs.refreshTtlSeconds;
			this.setJwtCookies(
				apiReq,
				{
					accessToken: result.tokens.accessToken,
					refreshToken: result.tokens.refreshToken
				},
				{
					sessionCookie: cookiePrefs.sessionCookie ?? false,
					refreshTtlSeconds: refreshTtlForCookie
				}
			);
			const publicUser = this.storage.filterUser(user) as unknown as PublicUser;
			return [200, { ...result.tokens, user: publicUser }];
		}

		const extras = result as Record<string, unknown>;
		const extrasPrefs = this.sessionPrefsFromRecord(extras);
		const metadataPrefs = this.mergeSessionPreferences(sessionPrefs, extrasPrefs);
		const metadata: TokenIssueOptions = {
			domain: toStringOrNull(extras.domain) ?? params.domain,
			fingerprint: toStringOrNull(extras.fingerprint) ?? params.fingerprint,
			label: toStringOrNull(extras.label) ?? params.label,
			browser: toStringOrNull(extras.browser) ?? params.browser,
			device: toStringOrNull(extras.device) ?? params.device,
			ip: toStringOrNull(extras.ip) ?? params.ip,
			os: toStringOrNull(extras.os) ?? params.os,
			loginType: 'passkey',
			...metadataPrefs
		};
		const tokens = await this.issueTokens(apiReq, user, metadata);
		const publicUser = this.storage.filterUser(user) as unknown as PublicUser;
		return [200, { ...tokens, user: publicUser }];
	}

	private async getPasskeys(apiReq: ApiRequest): Promise<[number, ApiPasskeyListRes]> {
		if (typeof this.storage.listUserCredentials !== 'function') {
			throw new ApiError({
				code: 501,
				message: 'Passkey credential listing is not configured'
			});
		}
		const { userId } = await this.resolveActorContext(apiReq);
		const credentials = await this.storage.listUserCredentials(userId);
		const safeCredentials: ApiPasskeyCredential[] = credentials.map((credential) => {
			const bufferId = this.normalizeCredentialId(credential.credentialId);
			return {
				id: isoBase64URL.fromBuffer(new Uint8Array(bufferId)),
				transports: credential.transports,
				backedUp: credential.backedUp,
				deviceType: credential.deviceType,
				createdAt: this.toIsoDate(credential.createdAt),
				updatedAt: this.toIsoDate(credential.updatedAt)
			};
		});
		return [200, { credentials: safeCredentials }];
	}

	private async deletePasskey(apiReq: ApiRequest): Promise<[number, ApiPasskeyDeleteRes]> {
		if (
			typeof this.storage.listUserCredentials !== 'function' ||
			typeof this.storage.deletePasskeyCredential !== 'function'
		) {
			throw new ApiError({
				code: 501,
				message: 'Passkey credential management is not configured'
			});
		}

		const { userId } = await this.resolveActorContext(apiReq);
		const credentialId = this.validateCredentialId(apiReq);
		const bufferId = Buffer.from(isoBase64URL.toBuffer(credentialId));
		const credentials = await this.storage.listUserCredentials(userId);
		const owns = credentials.some((credential) => {
			const candidateId = this.normalizeCredentialId(credential.credentialId);
			return isoBase64URL.fromBuffer(new Uint8Array(candidateId)) === credentialId;
		});
		if (!owns) {
			throw new ApiError({ code: 404, message: 'Passkey not found' });
		}
		const deleted = await this.storage.deletePasskeyCredential(bufferId);
		return [200, { deleted }];
	}

	private async postImpersonation(apiReq: ApiRequest): Promise<[number, ApiLoginRes<PublicUser>]> {
		this.assertAuthReady();
		const { targetIdentifier, metadata } = this.parseImpersonationRequest(apiReq);
		const actor = await this.resolveActorContext(apiReq);
		const targetUser = await this.getUserOrThrow(targetIdentifier, 'Target user not found');
		await this.ensureImpersonationAllowed(apiReq, actor.user, targetUser);
		const impersonationMetadata: TokenIssueOptions = {
			...metadata,
			ruid: String(actor.userId),
			loginType: metadata.loginType ?? 'impersonation'
		};
		const tokens = await this.issueTokens(apiReq, targetUser, impersonationMetadata);
		const publicUser = this.storage.filterUser(targetUser) as unknown as PublicUser;
		return [200, { ...tokens, user: publicUser }];
	}

	private async deleteImpersonation(apiReq: ApiRequest): Promise<[number, ApiLoginRes<PublicUser>]> {
		this.assertAuthReady();
		if (!apiReq.isImpersonating()) {
			throw new ApiError({
				code: 400,
				message: 'Not currently impersonating'
			});
		}
		// Revoke the active impersonation refresh token before issuing new real-user tokens
		// so that a captured impersonation token cannot be reused after impersonation ends.
		const impersonationRefreshToken = apiReq.authToken?.refreshToken ?? this.extractRefreshToken(apiReq, {});
		if (impersonationRefreshToken) {
			await this.server.deleteToken({
				refreshToken: impersonationRefreshToken
			});
		}
		const actor = await this.resolveActorContext(apiReq);
		const query = (apiReq.req.query ?? {}) as Record<string, unknown>;
		const metadata = this.buildImpersonationMetadata(query as ImpersonationMetadataBody);
		metadata.loginType = metadata.loginType ?? 'impersonation-end';
		const tokens = await this.issueTokens(apiReq, actor.user, metadata);
		const publicUser = this.storage.filterUser(actor.user) as unknown as PublicUser;
		return [200, { ...tokens, user: publicUser }];
	}

	private async getUserFromPasskey(
		result: PasskeyVerificationResult,
		params: PasskeyVerificationParams
	): Promise<UserEntity> {
		if (result.userId !== undefined) {
			return this.getUserOrThrow(result.userId, 'User not found for passkey verification');
		}
		if (result.login) {
			return this.getUserOrThrow(result.login, 'User not found for passkey verification');
		}
		if (params.userId !== undefined) {
			return this.getUserOrThrow(params.userId, 'User not found for passkey verification');
		}
		if (params.login) {
			return this.getUserOrThrow(params.login, 'User not found for passkey verification');
		}
		throw new ApiError({
			code: 500,
			message: 'Passkey response missing user reference'
		});
	}

	private async postOAuthStart(apiReq: ApiRequest): Promise<[number, OAuthStartResult]> {
		if (typeof this.server.initiateOAuth !== 'function') {
			throw new ApiError({
				code: 501,
				message: 'External OAuth support is not configured'
			});
		}
		const params: OAuthStartParams = {
			provider: apiReq.req.params?.provider as string,
			redirectUri: toStringOrNull((apiReq.req.body as OAuthStartBody)?.redirectUri) ?? undefined,
			scope: this.normalizeScope((apiReq.req.body as OAuthStartBody)?.scope),
			state: toStringOrNull((apiReq.req.body as OAuthStartBody)?.state) ?? undefined,
			extras:
				typeof (apiReq.req.body as OAuthStartBody)?.extras === 'object'
					? ((apiReq.req.body as OAuthStartBody).extras as Record<string, unknown>)
					: undefined
		};

		// provider is guaranteed present and non-empty by params schema

		const result = await this.server.initiateOAuth(params);
		return [200, result];
	}

	private async postOAuthCallback(apiReq: ApiRequest): Promise<[number, OAuthCallbackResult<PublicUser>]> {
		if (typeof this.server.completeOAuth !== 'function') {
			throw new ApiError({
				code: 501,
				message: 'External OAuth support is not configured'
			});
		}
		const params: OAuthCallbackParams = {
			provider: apiReq.req.params?.provider as string,
			query: apiReq.req.query as Record<string, string | string[]>,
			body: (apiReq.req.body ?? {}) as Record<string, unknown>
		};

		const result = await this.server.completeOAuth(params);

		if (result.tokens?.accessToken && result.tokens.refreshToken) {
			this.setJwtCookies(apiReq, {
				accessToken: result.tokens.accessToken,
				refreshToken: result.tokens.refreshToken
			});
		}

		return [200, result];
	}

	private async postOAuthAuthorize(apiReq: ApiRequest): Promise<[number, ApiOAuthAuthorizeRes]> {
		if (typeof this.storage.getClient !== 'function' || typeof this.storage.createAuthCode !== 'function') {
			throw new ApiError({
				code: 501,
				message: 'OAuth authorization storage is not configured'
			});
		}

		await this.applyRateLimit(apiReq, 'oauth-authorize');

		const body = (apiReq.req.body ?? {}) as OAuthAuthorizeBody;
		// clientId and redirectUri are guaranteed present and non-empty by JSON Schema
		const clientId = body.clientId as string;
		const redirectUri = body.redirectUri as string;
		const scope = toScopeArray(body.scope) ?? [];
		const state = toStringOrNull(body.state) ?? undefined;
		const { codeChallenge, codeChallengeMethod: resolvedCodeChallengeMethod } = this.resolveAuthorizePkce(body);

		const client = await this.storage.getClient(clientId);
		if (!client) {
			throw new ApiError({ code: 400, message: 'Unknown client_id' });
		}
		this.assertRedirectUriAllowed(client, redirectUri);
		if (!(client.hasSecret ?? false) && !codeChallenge) {
			throw new ApiError({
				code: 400,
				message: 'PKCE is required for public clients'
			});
		}

		const resolvedScope = this.resolveScope(client, scope);

		const user = await this.resolveUserForOAuth(apiReq, body);

		const codeRecord = await this.storage.createAuthCode({
			clientId,
			userId: this.storage.getUserId(user),
			redirectUri,
			scope: resolvedScope,
			codeChallenge,
			codeChallengeMethod: resolvedCodeChallengeMethod,
			expiresInSeconds: 300
		});

		const redirect = new URL(redirectUri);
		redirect.searchParams.set('code', codeRecord.code);
		if (state) {
			redirect.searchParams.set('state', state);
		}

		return [200, { code: codeRecord.code, redirectUri: redirect.toString(), state }];
	}

	private async postOAuthToken(apiReq: ApiRequest): Promise<[number, ApiOAuthTokenRes]> {
		await this.applyRateLimit(apiReq, 'oauth-token');
		if (typeof this.storage.getClient !== 'function' || typeof this.storage.consumeAuthCode !== 'function') {
			throw new ApiError({
				code: 501,
				message: 'OAuth token storage is not configured'
			});
		}

		const body = (apiReq.req.body ?? {}) as OAuthTokenBody;
		// grant_type is guaranteed to be 'authorization_code' | 'refresh_token' by JSON Schema
		const grantType = body.grant_type as string;

		const { client, clientSecretProvided } = await this.resolveClientAuthentication(apiReq, body);

		switch (grantType) {
			case 'authorization_code':
				return this.handleAuthorizationCodeGrant(apiReq, body, client, clientSecretProvided);
			case 'refresh_token':
				return this.handleRefreshTokenGrant(apiReq, body, client);
			default:
				throw new ApiError({
					code: 400,
					message: `Unsupported grant_type: ${grantType}`
				});
		}
	}

	private async handleAuthorizationCodeGrant(
		apiReq: ApiRequest,
		body: OAuthTokenBody,
		client: OAuthClient,
		clientSecretProvided: boolean
	): Promise<[number, ApiOAuthTokenRes]> {
		const code = toStringOrNull(body.code);
		const redirectUri = toStringOrNull(body.redirect_uri);
		const codeVerifier = toStringOrNull(body.code_verifier);
		const consumeAuthCode = this.storage.consumeAuthCode?.bind(this.storage);

		if (!consumeAuthCode) {
			throw new ApiError({
				code: 501,
				message: 'OAuth token storage is not configured'
			});
		}

		if (!code) {
			throw new ApiError({
				code: 400,
				message: 'code is required for authorization_code grant'
			});
		}
		if (!redirectUri) {
			throw new ApiError({
				code: 400,
				message: 'redirect_uri is required for authorization_code grant'
			});
		}

		this.assertRedirectUriAllowed(client, redirectUri);

		const record = await consumeAuthCode(code, client.clientId);
		if (!record) {
			throw new ApiError({
				code: 400,
				message: 'Invalid or expired authorization code'
			});
		}

		if (record.redirectUri !== redirectUri) {
			throw new ApiError({ code: 400, message: 'redirect_uri mismatch' });
		}

		if (record.codeChallenge) {
			if (!codeVerifier) {
				throw new ApiError({
					code: 400,
					message: 'code_verifier is required for this authorization code'
				});
			}
			if (record.codeChallengeMethod === 'S256') {
				if (sha256Base64Url(codeVerifier) !== record.codeChallenge) {
					throw new ApiError({
						code: 400,
						message: 'code_verifier does not match challenge'
					});
				}
			} else if (record.codeChallengeMethod === 'plain') {
				if (!this.allowInsecurePkcePlain) {
					throw new ApiError({
						code: 400,
						message: 'PKCE plain is not permitted'
					});
				}
				if (codeVerifier !== record.codeChallenge) {
					throw new ApiError({
						code: 400,
						message: 'code_verifier does not match challenge'
					});
				}
			} else {
				throw new ApiError({
					code: 400,
					message: 'Invalid or missing code_challenge_method'
				});
			}
		} else if (!(client.hasSecret ?? false)) {
			throw new ApiError({
				code: 400,
				message: 'PKCE is required for public clients'
			});
		} else if (!clientSecretProvided) {
			throw new ApiError({
				code: 400,
				message: 'Client authentication required when no PKCE challenge present'
			});
		}

		const user = await this.getUserOrThrow(record.userId, 'User not found');
		const resolvedScope = Array.isArray(record.scope) ? record.scope : [];
		const tokens = await this.issueTokens(apiReq, user, {
			clientId: client.clientId,
			scope: resolvedScope,
			label: resolvedScope.join(' '),
			loginType: 'oauth'
		});

		this.clearOAuthCookies(apiReq);

		return [200, this.buildTokenResponse(tokens, client, resolvedScope)];
	}

	private async handleRefreshTokenGrant(
		apiReq: ApiRequest,
		body: OAuthTokenBody,
		client: OAuthClient
	): Promise<[number, ApiOAuthTokenRes]> {
		const refreshToken = toStringOrNull(body.refresh_token);
		if (!refreshToken) {
			throw new ApiError({
				code: 400,
				message: 'refresh_token is required for refresh_token grant'
			});
		}

		const stored = await this.server.getToken({
			refreshToken,
			clientId: client.clientId
		});
		if (!stored) {
			throw new ApiError({ code: 400, message: 'Invalid refresh_token' });
		}

		const claims = this.verifyRefreshTokenOrThrow(refreshToken);

		if (stored.clientId && stored.clientId !== client.clientId) {
			throw new ApiError({
				code: 400,
				message: 'Refresh token issued to another client'
			});
		}

		// Delete the token immediately after verification to narrow the TOCTOU window.
		const deleted = await this.server.deleteToken({ refreshToken });
		if (deleted === 0) {
			throw new ApiError({ code: 401, message: 'Invalid refresh token' });
		}

		const user = await this.getUserOrThrow(stored.userId ?? claims.uid, 'User not found');
		const tokens = await this.issueTokens(apiReq, user, {
			clientId: client.clientId,
			scope: stored.scope,
			label: Array.isArray(stored.scope) ? stored.scope.join(' ') : stored.label,
			fingerprint: stored.fingerprint,
			sessionId: stored.sessionId,
			loginType: stored.loginType ?? 'oauth'
		});

		this.clearOAuthCookies(apiReq);

		const scope = Array.isArray(stored.scope) ? stored.scope : [];

		return [200, this.buildTokenResponse(tokens, client, scope)];
	}

	private clearOAuthCookies(apiReq: ApiRequest): void {
		this.setJwtCookies(apiReq, { accessToken: null, refreshToken: null });
	}

	private buildTokenResponse(tokens: TokenPair, client: OAuthClient, scope: string[]): ApiOAuthTokenRes {
		const conf = this.server.config;
		return {
			access_token: tokens.accessToken,
			refresh_token: tokens.refreshToken,
			token_type: 'Bearer',
			expires_in: conf.accessExpiry,
			scope: scope.join(' '),
			client_id: client.clientId
		};
	}

	private resolveScope(client: OAuthClient, requested: string[]): string[] {
		const allowed = Array.isArray(client.scope) ? client.scope : [];
		if (allowed.length === 0) {
			if (requested.length > 0) {
				throw new ApiError({
					code: 400,
					message: 'Requested scope is not permitted for this client'
				});
			}
			return [];
		}
		if (requested.length === 0) {
			return allowed;
		}
		if (requested.some((entry) => !allowed.includes(entry))) {
			throw new ApiError({
				code: 400,
				message: 'Requested scope is not permitted for this client'
			});
		}
		return requested;
	}

	private async resolveClientAuthentication(
		apiReq: ApiRequest,
		body: OAuthTokenBody
	): Promise<{ client: OAuthClient; clientSecretProvided: boolean }> {
		if (typeof this.storage.getClient !== 'function') {
			throw new ApiError({
				code: 501,
				message: 'OAuth client storage is not configured'
			});
		}

		let clientId: string | null = null;
		let clientSecret: string | null = null;
		let secretProvided = false;

		const header = apiReq.req.headers.authorization;
		if (typeof header === 'string' && header.startsWith('Basic ')) {
			const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
			const idx = decoded.indexOf(':');
			if (idx === -1) {
				throw new ApiError({
					code: 400,
					message: 'Invalid basic authorization header'
				});
			}
			clientId = decoded.slice(0, idx);
			clientSecret = decoded.slice(idx + 1);
			secretProvided = true;
		}

		if (!clientId) {
			clientId = toStringOrNull(body.client_id);
		}
		if (clientSecret === null && typeof body.client_secret === 'string') {
			clientSecret = body.client_secret;
			secretProvided = true;
		}

		if (!clientId) {
			throw new ApiError({ code: 400, message: 'client_id is required' });
		}

		const client = await this.storage.getClient(clientId);
		if (!client) {
			throw new ApiError({ code: 400, message: 'Unknown client_id' });
		}

		const requiresSecret = client.hasSecret ?? false;
		if (requiresSecret) {
			if (!secretProvided) {
				throw new ApiError({
					code: 400,
					message: 'Client authentication is required'
				});
			}
			const verifySecret = this.storage.verifyClientSecret;
			if (typeof verifySecret !== 'function' || !this.storageImplements('verifyClientSecret')) {
				throw new ApiError({
					code: 501,
					message: 'OAuth client secret verification is not configured'
				});
			}
			const valid = await verifySecret.call(this.storage, client, clientSecret);
			if (!valid) {
				throw new ApiError({
					code: 401,
					message: 'Invalid client credentials'
				});
			}
		}

		return { client, clientSecretProvided: secretProvided };
	}

	private assertRedirectUriAllowed(client: OAuthClient, redirectUri: string): void {
		if (client.redirectUris.length === 0) {
			throw new ApiError({
				code: 400,
				message: 'Client has no registered redirect URIs'
			});
		}
		if (!client.redirectUris.includes(redirectUri)) {
			throw new ApiError({
				code: 400,
				message: 'redirect_uri not registered for client'
			});
		}
	}

	private async resolveUserForOAuth(apiReq: ApiRequest, body: OAuthAuthorizeBody): Promise<UserEntity> {
		const refreshToken = this.extractRefreshToken(apiReq, body as Record<string, unknown>);
		if (refreshToken) {
			const verify = this.server.jwtVerify<TokenClaims>(refreshToken, this.server.config.refreshSecret);
			if (!verify.success || !verify.data) {
				throw new ApiError({
					code: 401,
					message: 'Invalid or expired refresh token'
				});
			}
			const stored = await this.server.getToken({ refreshToken });
			if (stored) {
				return this.getUserOrThrow(stored.userId ?? verify.data.uid, 'User not found for authorization');
			}
		}

		const login = toStringOrNull(body.login);
		const password = toStringOrNull(body.password);
		if (login && password) {
			const user = await this.verifyCredentials(login, password);
			if (!user) {
				throw new ApiError({
					code: 400,
					message: 'Invalid credentials'
				});
			}
			return user;
		}

		throw new ApiError({
			code: 401,
			message: 'Authorization requires user authentication'
		});
	}

	private hasPasskeyService(): boolean {
		const storageHints = this.storage as PasskeyStorageHints;
		if (storageHints.passkeyService || storageHints.passkeyStore) {
			return true;
		}
		if (storageHints.adapter?.passkeyService || storageHints.adapter?.passkeyStore) {
			return true;
		}
		return false;
	}

	private hasOAuthStore(): boolean {
		const storageHints = this.storage as OAuthStorageHints;
		if (storageHints.oauthStore) {
			return true;
		}
		if (storageHints.adapter?.oauthStore) {
			return true;
		}
		return false;
	}

	private storageImplements(key: keyof AuthAdapter<UserEntity, PublicUser>): boolean {
		const candidate = this.storage[key];
		if (typeof candidate !== 'function') {
			return false;
		}
		if (!(this.storage instanceof BaseAuthAdapter)) {
			return true;
		}
		const baseImpl = BaseAuthAdapter.prototype[key as keyof BaseAuthAdapter<UserEntity, PublicUser>];
		return candidate !== baseImpl;
	}

	private storageImplementsAll(keys: Array<keyof AuthAdapter<UserEntity, PublicUser>>): boolean {
		return keys.every((key) => this.storageImplements(key));
	}

	private async applyRateLimit(apiReq: ApiRequest, endpoint: AuthRateLimitEndpoint): Promise<void> {
		if (!this.rateLimitHook) {
			return;
		}
		await this.rateLimitHook({ apiReq, endpoint });
	}

	private resolvePkceChallengeMethod(value: string | undefined): 'plain' | 'S256' | undefined {
		if (value === 'S256') {
			return 'S256';
		}
		if (value === 'plain') {
			if (!this.allowInsecurePkcePlain) {
				throw new ApiError({
					code: 400,
					message: 'PKCE plain is not permitted'
				});
			}
			return 'plain';
		}
		return undefined;
	}

	override defineRoutes(): ApiRoute[] {
		const routes: ApiRoute[] = [];

		const coreAuthSupported =
			this.storageImplementsAll([
				'getUser',
				'getUserPasswordHash',
				'getUserId',
				'verifyPassword',
				'filterUser'
			]) &&
			(this.server.getTokenStore() !== null ||
				this.storageImplementsAll(['storeToken', 'getToken', 'deleteToken']));

		if (!coreAuthSupported) {
			return routes;
		}

		routes.push(
			{
				method: 'post',
				path: '/v1/login',
				handler: (req) => this.postLogin(req),
				auth: { type: 'none', req: 'any' },
				schema: {
					body: loginBodySchema,
					querystring: emptyObjectSchema
				}
			},
			{
				method: 'post',
				path: '/v1/refresh',
				handler: (req) => this.postRefresh(req),
				auth: { type: 'none', req: 'any' },
				schema: {
					body: refreshBodySchema,
					querystring: emptyObjectSchema
				}
			},
			{
				method: 'post',
				path: '/v1/logout',
				handler: (req) => this.postLogout(req),
				auth: { type: 'maybe', req: 'any' },
				schema: {
					body: logoutBodySchema,
					querystring: emptyObjectSchema
				}
			},
			{
				method: 'get',
				path: '/v1/me',
				handler: (req) => this.getMe(req),
				auth: { type: 'yes', req: 'any' },
				schema: { querystring: emptyObjectSchema }
			},
			{
				method: 'get',
				path: '/v1/me/sessions',
				handler: (req) => this.getSessions(req),
				auth: { type: 'yes', req: 'any' },
				schema: { querystring: emptyObjectSchema }
			},
			{
				method: 'delete',
				path: '/v1/me/sessions/:sessionId',
				handler: (req) => this.deleteSession(req),
				auth: { type: 'yes', req: 'any' },
				schema: {
					params: sessionParamsSchema,
					querystring: emptyObjectSchema
				}
			},
			{
				method: 'post',
				path: '/v1/impersonations',
				handler: (req) => this.postImpersonation(req),
				auth: { type: 'strict', req: 'any' },
				schema: {
					body: impersonateBodySchema,
					querystring: emptyObjectSchema
				}
			},
			{
				method: 'delete',
				path: '/v1/impersonations',
				handler: (req) => this.deleteImpersonation(req),
				auth: { type: 'strict', req: 'any' },
				schema: { querystring: deleteImpersonationQuerySchema }
			}
		);

		const passkeysSupported =
			this.hasPasskeyService() &&
			this.storageImplements('createPasskeyChallenge') &&
			this.storageImplements('getPasskeyChallenge') &&
			this.storageImplements('verifyPasskeyResponse');
		const passkeyCredentialsSupported =
			passkeysSupported &&
			this.storageImplements('listUserCredentials') &&
			this.storageImplements('deletePasskeyCredential');
		if (passkeysSupported) {
			routes.push(
				{
					method: 'post',
					path: '/v1/passkeys/challenge',
					handler: (req) => this.postPasskeyChallenge(req),
					auth: { type: 'none', req: 'any' },
					schema: {
						body: passkeyChallengeBodySchema,
						querystring: emptyObjectSchema
					}
				},
				{
					method: 'post',
					path: '/v1/passkeys/verify',
					handler: (req) => this.postPasskeyVerify(req),
					auth: { type: 'none', req: 'any' },
					schema: {
						body: passkeyVerifyBodySchema,
						querystring: emptyObjectSchema
					}
				}
			);
			if (passkeyCredentialsSupported) {
				routes.push(
					{
						method: 'get',
						path: '/v1/passkeys',
						handler: (req) => this.getPasskeys(req),
						auth: { type: 'strict', req: 'any' },
						schema: { querystring: emptyObjectSchema }
					},
					{
						method: 'delete',
						path: '/v1/passkeys/:credentialId',
						handler: (req) => this.deletePasskey(req),
						auth: { type: 'strict', req: 'any' },
						schema: {
							params: passkeyCredentialParamsSchema,
							querystring: emptyObjectSchema
						}
					}
				);
			}
		}

		const externalOAuthSupported =
			typeof this.server.initiateOAuth === 'function' && typeof this.server.completeOAuth === 'function';
		if (externalOAuthSupported) {
			routes.push(
				{
					method: 'post',
					path: '/v1/oauth2/:provider/start',
					handler: (req) => this.postOAuthStart(req),
					auth: { type: 'none', req: 'any' },
					schema: {
						body: oauthStartBodySchema,
						params: oauthProviderParamsSchema,
						querystring: emptyObjectSchema
					}
				},
				{
					method: 'post',
					path: '/v1/oauth2/:provider/callback',
					handler: (req) => this.postOAuthCallback(req),
					auth: { type: 'none', req: 'any' },
					schema: { params: oauthProviderParamsSchema }
				}
			);
		}

		const oauthStorageSupported =
			this.hasOAuthStore() &&
			this.storageImplements('getClient') &&
			this.storageImplements('createAuthCode') &&
			this.storageImplements('consumeAuthCode');
		if (oauthStorageSupported) {
			routes.push(
				{
					method: 'post',
					path: '/v1/oauth2/authorize',
					handler: (req) => this.postOAuthAuthorize(req),
					auth: { type: 'maybe', req: 'any' },
					schema: {
						body: oauthAuthorizeBodySchema,
						querystring: emptyObjectSchema
					}
				},
				{
					method: 'post',
					path: '/v1/oauth2/token',
					handler: (req) => this.postOAuthToken(req),
					auth: { type: 'none', req: 'any' },
					schema: {
						body: oauthTokenBodySchema,
						querystring: emptyObjectSchema
					}
				}
			);
		}

		return routes;
	}
}
