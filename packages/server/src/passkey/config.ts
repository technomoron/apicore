import type { PasskeyServiceConfig } from './types.js';

const DEFAULT_PASSKEY_CONFIG: PasskeyServiceConfig = {
	rpId: 'localhost',
	rpName: 'API Server',
	origins: ['http://localhost:5173'],
	timeoutMs: 5 * 60 * 1000,
	userVerification: 'preferred'
};

function isOriginString(origin: unknown): origin is string {
	return typeof origin === 'string' && origin.trim().length > 0;
}

export function normalizePasskeyConfig(config: Partial<PasskeyServiceConfig> = {}): PasskeyServiceConfig {
	const candidateOrigins =
		Array.isArray(config.origins) && config.origins.length > 0 ? config.origins.filter(isOriginString) : null;

	return {
		rpId: config.rpId?.trim() || DEFAULT_PASSKEY_CONFIG.rpId,
		rpName: config.rpName?.trim() || DEFAULT_PASSKEY_CONFIG.rpName,
		origins: candidateOrigins ? candidateOrigins.map((origin) => origin.trim()) : DEFAULT_PASSKEY_CONFIG.origins,
		timeoutMs:
			typeof config.timeoutMs === 'number' && config.timeoutMs > 0
				? config.timeoutMs
				: DEFAULT_PASSKEY_CONFIG.timeoutMs,
		userVerification: config.userVerification ?? DEFAULT_PASSKEY_CONFIG.userVerification,
		debug: Boolean(config.debug)
	};
}
