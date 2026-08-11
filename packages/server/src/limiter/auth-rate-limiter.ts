import { ApiError, type ApiRequest } from '../apicore-server.js';

import { FixedWindowRateLimiter } from './fixed-window.js';

type AuthRateLimitEndpoint = 'login' | 'passkey-challenge' | 'oauth-token' | 'oauth-authorize';

export interface AuthRateLimitConfig {
	windowSec?: number;
	max?: number;
}

export function createAuthRateLimitHook(
	config: Partial<Record<AuthRateLimitEndpoint, AuthRateLimitConfig>>,
	limiter?: FixedWindowRateLimiter
): (ctx: { apiReq: ApiRequest; endpoint: string }) => void {
	if (!config || Object.keys(config).length === 0) {
		return () => {};
	}

	const instance = limiter ?? new FixedWindowRateLimiter();

	return (ctx: { apiReq: ApiRequest; endpoint: string }) => {
		const endpointConfig = config[ctx.endpoint as AuthRateLimitEndpoint];
		if (!endpointConfig) {
			return;
		}
		const windowSec = endpointConfig.windowSec ?? 0;
		const max = endpointConfig.max ?? 0;
		if (windowSec <= 0 || max <= 0) {
			return;
		}

		const clientIp = ctx.apiReq.getClientIp() ?? 'unknown';

		const key = `${ctx.endpoint}:${clientIp}`;
		const decision = instance.check(key, max, windowSec * 1000);
		if (!decision.allowed) {
			throw new ApiError({
				code: 429,
				message: 'Too many requests; try again later',
				data: { retryAfterSec: decision.retryAfterSec }
			});
		}
	};
}
