import type { ApiCookieOptions } from './apicore-server.js';

export interface AuthCookieConfig {
	cookieSecure?: boolean | 'auto';
	cookieSameSite?: 'lax' | 'strict' | 'none';
	cookieHttpOnly?: boolean;
	cookieDomain?: string;
	cookiePath?: string;
	devMode?: boolean;
	trustProxy?: boolean | number;
}

function firstHeaderValue(value: string | string[] | undefined): string {
	if (typeof value === 'string') {
		return value;
	}
	if (Array.isArray(value)) {
		return value[0] ?? '';
	}
	return '';
}

function resolveOriginHostname(origin: string): string | null {
	try {
		const url = new URL(origin);
		const hostname = url.hostname.trim().toLowerCase();
		return hostname.length > 0 ? hostname : null;
	} catch {
		return null;
	}
}

function isLocalhostOrigin(origin: string): boolean {
	const hostname = resolveOriginHostname(origin);
	if (!hostname) {
		return false;
	}
	return hostname === 'localhost' || hostname.endsWith('.localhost');
}

export function buildAuthCookieOptions(
	config: AuthCookieConfig,
	req: {
		headers: Record<string, string | string[] | undefined>;
		protocol?: string;
	}
): ApiCookieOptions {
	const forwardedProtocols = firstHeaderValue(req.headers['x-forwarded-proto'])
		.split(',')
		.map((value) => value.trim().toLowerCase())
		.filter(Boolean);
	const forwardedIndex =
		typeof config.trustProxy === 'number'
			? Math.max(0, forwardedProtocols.length - Math.max(0, config.trustProxy))
			: 0;
	const forwardedProto =
		config.trustProxy === true || (typeof config.trustProxy === 'number' && config.trustProxy > 0)
			? forwardedProtocols[forwardedIndex]
			: undefined;
	const isHttps = forwardedProto === 'https' || req.protocol === 'https';
	const origin = firstHeaderValue(req.headers.origin ?? req.headers.referer);

	let secure: boolean;
	if (config.cookieSecure === true) {
		secure = true;
	} else if (config.cookieSecure === false) {
		secure = false;
	} else {
		secure = isHttps;
	}
	let sameSite: ApiCookieOptions['sameSite'] = config.cookieSameSite ?? 'lax';
	if (sameSite !== 'lax' && sameSite !== 'strict' && sameSite !== 'none') {
		sameSite = 'lax';
	}
	let resolvedSecure = secure;
	if (sameSite === 'none' && resolvedSecure !== true) {
		// Modern browsers reject SameSite=None cookies unless Secure is set.
		resolvedSecure = true;
	}
	const options: ApiCookieOptions = {
		httpOnly: config.cookieHttpOnly ?? true,
		secure: resolvedSecure,
		sameSite,
		domain: config.cookieDomain || undefined,
		path: config.cookiePath || '/',
		maxAge: undefined
	};

	if (config.devMode && isLocalhostOrigin(origin)) {
		// Domain cookies do not work on localhost; avoid breaking local development when cookieDomain is set.
		options.domain = undefined;
	}

	return options;
}
