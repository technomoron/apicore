interface ClientInfoRequest {
	headers: Record<string, string | string[] | undefined>;
	ips?: string[];
	ip?: string;
	socket?: { remoteAddress?: string };
	connection?: { remoteAddress?: string };
}

export interface ClientAgentProfile {
	ua: string;
	browser: string;
	os: string;
	device: string;
}

export interface ClientInfo extends ClientAgentProfile {
	ip: string | null;
	ipchain: string[];
}

interface ApiRequestWithClientInfo {
	req: ClientInfoRequest;
	clientInfo?: ClientInfo;
}

function normalizeIpAddress(candidate: string): string | null {
	let value = candidate.trim();
	if (!value) {
		return null;
	}

	value = value.replace(/^"+|"+$/g, '').replace(/^'+|'+$/g, '');

	if (value.startsWith('::ffff:')) {
		value = value.slice(7);
	}

	if (value.startsWith('[') && value.endsWith(']')) {
		value = value.slice(1, -1);
	}

	const firstColon = value.indexOf(':');
	const lastColon = value.lastIndexOf(':');
	if (firstColon !== -1 && firstColon === lastColon) {
		const maybePort = value.slice(lastColon + 1);
		if (/^\d+$/.test(maybePort)) {
			value = value.slice(0, lastColon);
		}
	}

	value = value.trim();
	return value || null;
}

function extractForwardedFor(header: string | string[] | undefined): string[] {
	return extractForwardedParts(header, (part) => normalizeIpAddress(part));
}

function extractForwardedHeader(header: string | string[] | undefined): string[] {
	return extractForwardedParts(header, (part) => {
		const match = part.match(/for=([^;]+)/i);
		return match ? normalizeIpAddress(match[1]) : null;
	});
}

function extractForwardedParts(
	header: string | string[] | undefined,
	parse: (part: string) => string | null
): string[] {
	if (!header) {
		return [];
	}
	const values = Array.isArray(header) ? header : [header];
	const ips: string[] = [];
	for (const entry of values) {
		for (const part of entry.split(',')) {
			const normalized = parse(part);
			if (normalized) {
				ips.push(normalized);
			}
		}
	}
	return ips;
}

function uniqueIpCollector(): { result: string[]; push: (ip: string | null) => void } {
	const seen = new Set<string>();
	const result: string[] = [];
	return {
		result,
		push: (ip: string | null) => {
			if (!ip || seen.has(ip)) return;
			seen.add(ip);
			result.push(ip);
		}
	};
}

function detectBrowser(userAgent: string): string {
	const browserMatchers: Array<{
		label: string;
		pattern: RegExp;
		versionGroup?: number;
	}> = [
		{
			label: 'Edge',
			pattern: /(Edg|Edge|EdgiOS|EdgA)\/([\d.]+)/i,
			versionGroup: 2
		},
		{
			label: 'Chrome',
			pattern: /(Chrome|CriOS)\/([\d.]+)/i,
			versionGroup: 2
		},
		{
			label: 'Firefox',
			pattern: /(Firefox|FxiOS)\/([\d.]+)/i,
			versionGroup: 2
		},
		{
			label: 'Safari',
			pattern: /Version\/([\d.]+).*Safari/i,
			versionGroup: 1
		},
		{ label: 'Opera', pattern: /(OPR|Opera)\/([\d.]+)/i, versionGroup: 2 },
		{ label: 'Brave', pattern: /Brave\/([\d.]+)/i, versionGroup: 1 },
		{ label: 'Vivaldi', pattern: /Vivaldi\/([\d.]+)/i, versionGroup: 1 },
		{ label: 'Electron', pattern: /Electron\/([\d.]+)/i, versionGroup: 1 },
		{ label: 'Node', pattern: /Node\.js\/([\d.]+)/i, versionGroup: 1 },
		{ label: 'IE', pattern: /MSIE ([\d.]+)/i, versionGroup: 1 },
		{ label: 'IE', pattern: /Trident\/.*rv:([\d.]+)/i, versionGroup: 1 }
	];

	for (const matcher of browserMatchers) {
		const m = userAgent.match(matcher.pattern);
		if (m) {
			const version = matcher.versionGroup ? m[matcher.versionGroup] : '';
			return version ? `${matcher.label} ${version}` : matcher.label;
		}
	}
	return '';
}

function detectOs(userAgent: string): string {
	const osMatchers: Array<{
		label: string;
		pattern: RegExp;
		transform?: (match: RegExpMatchArray) => string;
	}> = [
		{
			label: 'Windows',
			pattern: /Windows NT ([\d.]+)/i,
			transform: (match) => `Windows ${match[1]}`
		},
		{
			label: 'iOS',
			pattern: /iPhone OS ([\d_]+)/i,
			transform: (match) => `iOS ${match[1].replace(/_/g, '.')}`
		},
		{
			label: 'iPadOS',
			pattern: /iPad; CPU OS ([\d_]+)/i,
			transform: (match) => `iPadOS ${match[1].replace(/_/g, '.')}`
		},
		{
			label: 'macOS',
			pattern: /Mac OS X ([\d_]+)/i,
			transform: (match) => `macOS ${match[1].replace(/_/g, '.')}`
		},
		{
			label: 'Android',
			pattern: /Android ([\d.]+)/i,
			transform: (match) => `Android ${match[1]}`
		},
		{
			label: 'ChromeOS',
			pattern: /CrOS [^ ]+ ([\d.]+)/i,
			transform: (match) => `ChromeOS ${match[1]}`
		},
		{ label: 'Linux', pattern: /Linux/i },
		{ label: 'Unix', pattern: /X11/i }
	];

	for (const matcher of osMatchers) {
		const m = userAgent.match(matcher.pattern);
		if (m) {
			return matcher.transform ? matcher.transform(m) : matcher.label;
		}
	}
	return '';
}

function detectDevice(userAgent: string, osLabel: string): string {
	if (/iPhone/i.test(userAgent)) {
		return 'iPhone';
	}
	if (/iPad/i.test(userAgent)) {
		return 'iPad';
	}
	if (/iPod/i.test(userAgent)) {
		return 'iPod';
	}
	if (/Android/i.test(userAgent)) {
		const match = userAgent.match(/;\s*([^;]+)\s+Build/i);
		if (match) {
			return match[1];
		}
		return 'Android Device';
	}
	if (/Macintosh/i.test(userAgent)) {
		return 'Mac';
	}
	if (/Windows/i.test(userAgent)) {
		return 'PC';
	}
	if (/CrOS/i.test(userAgent)) {
		return 'Chromebook';
	}
	return osLabel;
}

function parseClientAgent(userAgentHeader: string | string[] | undefined): ClientAgentProfile {
	const raw = Array.isArray(userAgentHeader) ? userAgentHeader[0] : userAgentHeader;
	const ua = typeof raw === 'string' ? raw.trim() : '';
	if (!ua) {
		return { ua: '', browser: '', os: '', device: '' };
	}
	const os = detectOs(ua);
	const browser = detectBrowser(ua);
	const device = detectDevice(ua, os);
	return { ua, browser, os, device };
}

function isLoopbackAddress(ip: string): boolean {
	if (ip === '::1' || ip === '0:0:0:0:0:0:0:1') {
		return true;
	}
	if (ip === '0.0.0.0' || ip === '127.0.0.1') {
		return true;
	}
	if (ip.startsWith('127.')) {
		return true;
	}
	return false;
}

function collectSocketAddresses(req: ClientInfoRequest): string[] {
	const ips = uniqueIpCollector();

	if (Array.isArray(req.ips)) {
		for (const ip of req.ips) {
			ips.push(normalizeIpAddress(ip));
		}
	}
	if (typeof req.ip === 'string') {
		ips.push(normalizeIpAddress(req.ip));
	}
	const socketAddress = req.socket?.remoteAddress;
	if (typeof socketAddress === 'string') {
		ips.push(normalizeIpAddress(socketAddress));
	}
	const connectionAddress = req.connection?.remoteAddress;
	if (typeof connectionAddress === 'string') {
		ips.push(normalizeIpAddress(connectionAddress));
	}
	return ips.result;
}

function collectForwardedIps(req: ClientInfoRequest): string[] {
	const ips = uniqueIpCollector();

	for (const ip of extractForwardedFor(req.headers['x-forwarded-for'])) {
		ips.push(ip);
	}
	for (const ip of extractForwardedHeader(req.headers['forwarded'])) {
		ips.push(ip);
	}
	const realIp = req.headers['x-real-ip'];
	if (Array.isArray(realIp)) {
		for (const value of realIp) {
			ips.push(normalizeIpAddress(value));
		}
	} else if (typeof realIp === 'string') {
		ips.push(normalizeIpAddress(realIp));
	}
	return ips.result;
}

function collectNumericForwardedIps(req: ClientInfoRequest): string[] {
	const forwardedFor = extractForwardedFor(req.headers['x-forwarded-for']);
	if (forwardedFor.length > 0) {
		return forwardedFor;
	}
	const forwarded = extractForwardedHeader(req.headers['forwarded']);
	if (forwarded.length > 0) {
		return forwarded;
	}
	const realIp = req.headers['x-real-ip'];
	const values = Array.isArray(realIp) ? realIp : typeof realIp === 'string' ? [realIp] : [];
	return values.map(normalizeIpAddress).filter((value): value is string => Boolean(value));
}

function collectDirectPeerAddresses(req: ClientInfoRequest): string[] {
	const peers = uniqueIpCollector();
	for (const candidate of [req.socket?.remoteAddress, req.connection?.remoteAddress]) {
		if (typeof candidate === 'string') {
			peers.push(normalizeIpAddress(candidate));
		}
	}
	return peers.result;
}

function collectClientIpChain(req: ClientInfoRequest, trustProxy?: boolean | number): string[] {
	const socketIps = collectSocketAddresses(req);

	// trustProxy=false: ignore forwarded headers entirely
	if (trustProxy === false) {
		return socketIps;
	}

	// Numeric trust counts proxy hops from the application. Use one forwarding
	// header family and walk from the direct peer towards the client so
	// client-prepended entries outside the trusted depth are discarded.
	if (typeof trustProxy === 'number' && trustProxy >= 0) {
		if (trustProxy === 0) {
			return socketIps;
		}
		const fullChain = [...collectNumericForwardedIps(req), ...collectDirectPeerAddresses(req)];
		const firstTrustedClientIndex = Math.max(0, fullChain.length - trustProxy - 1);
		return fullChain.slice(firstTrustedClientIndex);
	}

	const forwardedIps = collectForwardedIps(req);

	// trustProxy=true or undefined: trust all (backwards-compatible default)
	const seen = new Set(forwardedIps);
	const result = [...forwardedIps];
	for (const ip of socketIps) {
		if (!seen.has(ip)) {
			seen.add(ip);
			result.push(ip);
		}
	}
	return result;
}

function selectClientIp(chain: string[]): string | null {
	for (const ip of chain) {
		if (!isLoopbackAddress(ip)) {
			return ip;
		}
	}
	return chain[0] ?? null;
}

function buildClientInfo(req: ClientInfoRequest, trustProxy?: boolean | number): ClientInfo {
	const agent = parseClientAgent(req.headers['user-agent']);
	const ipchain = collectClientIpChain(req, trustProxy);
	const ip = selectClientIp(ipchain);
	return {
		...agent,
		ip,
		ipchain
	};
}

export function ensureClientInfo(apiReq: ApiRequestWithClientInfo, trustProxy?: boolean | number): ClientInfo {
	if (!apiReq.clientInfo) {
		apiReq.clientInfo = buildClientInfo(apiReq.req, trustProxy);
	}
	return apiReq.clientInfo;
}
