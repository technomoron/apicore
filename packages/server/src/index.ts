export { default as ApiServer } from './apicore-server.js';
export { ApiError } from './apicore-server.js';
export { ApiModule } from './api-module.js';
export { rawRequest } from './base/raw-request.js';
export type { RawRequestOptions } from './base/raw-request.js';
export { HmacSigner, RequestSigner, RequestSignatureError } from './base/request-signing.js';
export type { HmacSignerOptions, RequestSignerOptions } from './base/request-signing.js';
export type { RequestSigningAlgorithm, RequestSigningLocation } from './base/request-signing.js';

export type {
	ApiErrorParams,
	ApiHandler,
	ApiHandlerRes,
	ApiHandlerResult,
	ApiKey,
	ApiServerConf,
	UploadCleanupMode,
	UploadPurgeSummary,
	ApiRequest,
	_ApiReply,
	ApiRoute,
	ApiRouteSchema,
	ApiRouteValidatorAdapter,
	ApiRouteValidatorContext,
	ApiAuthType,
	ApiAuthClass,
	ApiTokenData,
	ExtendedReq,
	ExpressApiRequest,
	ExpressApiLocals
} from './apicore-server.js';

export { MemoryApiKeyStore } from './api-key/memory.js';
export { JsonApiKeyStore } from './api-key/json.js';
export type { ApiKeyFile, ApiKeyRecord, ApiKeyStore, StoredApiKey } from './api-key/types.js';
export type { AuthIdentifier } from './auth-api/types.js';
export type { Token, TokenPair, TokenStatus } from './token/types.js';
export type { JwtSignResult, JwtVerifyResult, JwtDecodeResult } from './token/base.js';
export type { OAuthClient, AuthCodeData, AuthCodeRequest } from './oauth/types.js';

export type { AuthProviderModule } from './auth-api/module.js';

export { nullAuthAdapter, BaseAuthAdapter } from './auth-api/storage.js';
export { nullAuthModule, BaseAuthModule } from './auth-api/module.js';

export { CompositeAuthAdapter } from './auth-api/compat-auth-storage.js';
export { MemAuthStore } from './auth-api/mem-auth-store.js';
export { default as AuthModule } from './auth-api/auth-module.js';
export type {
	ApiLoginRes,
	ApiLogoutRes,
	ApiMeRes,
	ApiOAuthAuthorizeRes,
	ApiOAuthCallbackRes,
	ApiOAuthStartRes,
	ApiOAuthTokenRes,
	ApiPasskeyChallengeRes,
	ApiPasskeyDeleteRes,
	ApiPasskeyListRes,
	ApiPasskeyVerifyRes,
	ApiRefreshRes,
	ApiResponse,
	ApiRevokeSessionRes,
	ApiSessionsRes,
	SessionInfo
} from './common.js';
export type { OAuthStartParams, OAuthStartResult, OAuthCallbackParams, OAuthCallbackResult } from './oauth/types.js';

export type { BcryptHasherOptions, CreateUserInput, UpdateUserInput, PublicUserMapper } from './user/types.js';

export { UserStore } from './user/base.js';
export { MemoryUserStore } from './user/memory.js';
export type { MemoryUserAttributes, MemoryUserStoreOptions } from './user/memory.js';

export { TokenStore } from './token/base.js';
export { MemoryTokenStore } from './token/memory.js';

export { PasskeyService } from './passkey/service.js';
export { PasskeyStore } from './passkey/base.js';
export { MemoryPasskeyStore } from './passkey/memory.js';
export type {
	PasskeyServiceConfig,
	PasskeyChallengeRecord,
	PasskeyUserDescriptor,
	StoredPasskeyCredential,
	PasskeyChallenge,
	PasskeyChallengeParams,
	PasskeyVerificationParams,
	PasskeyVerificationResult
} from './passkey/types.js';

export { OAuthStore } from './oauth/base.js';
export { MemoryOAuthStore } from './oauth/memory.js';
export { OAuthAuthorizationServer, OAuthProtocolError } from './oauth/authorization-server.js';
export type {
	OAuthAuthorizationServerOptions,
	OAuthAuthorizationContext,
	OAuthAccessToken
} from './oauth/authorization-server.js';

export { FixedWindowRateLimiter } from './limiter/fixed-window.js';
export type { RateLimitDecision } from './limiter/fixed-window.js';
export { createAuthRateLimitHook } from './limiter/auth-rate-limiter.js';
export type { AuthRateLimitConfig } from './limiter/auth-rate-limiter.js';

export { TusUploadModule } from './upload/tus-module.js';
export { FileTusUploadStore } from './upload/file.js';
export {
	MemoryTusUploadStore,
	TusUploadCapacityError,
	TusUploadExceedsLengthError,
	TusUploadOffsetError
} from './upload/memory.js';
export type { MemoryTusUploadStoreOptions } from './upload/memory.js';
export type { TusUploadModuleOptions } from './upload/tus-module.js';
export type {
	TusMetadata,
	TusUploadRecord,
	TusCreateUploadInput,
	TusAppendInput,
	TusUploadStore,
	UploadPurgeResult
} from './upload/types.js';

export { JsonTokenStore } from './token/json.js';
export { OAuthPasswordLogin } from './oauth/password-login.js';
export type { OAuthPasswordLoginOptions } from './oauth/password-login.js';
export type { OAuthGrantContext } from './oauth/authorization-server.js';
export { verifyTotp } from './oauth/totp.js';
