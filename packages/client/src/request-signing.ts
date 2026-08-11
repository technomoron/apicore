const encoder = new TextEncoder();

export type RequestSigningAlgorithm = 'hmac-sha256';
export type RequestSigningLocation = 'header' | 'parameter';

export interface RequestSigningOptions {
	secret: string;
	algo?: RequestSigningAlgorithm;
	in?: RequestSigningLocation;
	signature?: string;
	timestamp?: string;
}

export abstract class RequestSigner {
	public abstract apply(
		input: RequestInfo,
		init: RequestInit,
		headers: Headers
	): Promise<{ input: RequestInfo; body: BodyInit | null | undefined }>;
}

function compareText(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function stableJson(value: unknown): string {
	if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? '';
	if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
	if (typeof value === 'object') {
		return `{${Object.entries(value as Record<string, unknown>)
			.sort(([left], [right]) => compareText(left, right))
			.map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`)
			.join(',')}}`;
	}
	return JSON.stringify(value) ?? '';
}

function stableValue(value: unknown): string {
	return typeof value === 'string' ? value : stableJson(value);
}

function bodyParameters(body: BodyInit | null | undefined): Array<[string, string]> {
	if (body === undefined || body === null || body === '') return [];
	if (body instanceof URLSearchParams) return Array.from(body.entries());
	if (typeof body !== 'string') {
		throw new TypeError('Signed requests support string and URLSearchParams bodies');
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(body) as unknown;
	} catch {
		return Array.from(new URLSearchParams(body).entries());
	}
	if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
		return [['body', stableValue(parsed)]];
	}
	return Object.entries(parsed as Record<string, unknown>).flatMap(([key, value]): Array<[string, string]> =>
		Array.isArray(value)
			? value.map((entry): [string, string] => [key, stableValue(entry)])
			: [[key, stableValue(value)]]
	);
}

function canonicalParameters(params: Array<[string, string]>, excludedNames: ReadonlySet<string>): string {
	params = params.filter(([name]) => !excludedNames.has(name));
	params.sort(([leftKey, leftValue], [rightKey, rightValue]) => {
		const keyOrder = compareText(leftKey, rightKey);
		return keyOrder === 0 ? compareText(leftValue, rightValue) : keyOrder;
	});
	const canonical = new URLSearchParams();
	for (const [key, value] of params) canonical.append(key, value);
	return canonical.toString();
}

export function canonicalRequestParameters(
	url: URL,
	body: BodyInit | null | undefined,
	excludedNames: ReadonlySet<string> = new Set()
): { query: string; body: string } {
	return {
		query: canonicalParameters([...url.searchParams.entries()], excludedNames),
		body: canonicalParameters(bodyParameters(body), excludedNames)
	};
}

export async function signRequest(
	secret: string,
	method: string,
	url: URL,
	timestamp: string,
	body: BodyInit | null | undefined,
	excludedNames?: ReadonlySet<string>
): Promise<string> {
	const params = canonicalRequestParameters(url, body, excludedNames);
	const content = `${method.toUpperCase()}\n${url.pathname}\n${timestamp}\n${params.query}\n${params.body}`;
	const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
		'sign'
	]);
	const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(content));
	return bytesToHex(new Uint8Array(signature));
}

function addParameter(body: BodyInit | null | undefined, name: string, value: string): BodyInit {
	if (body === undefined || body === null || body === '') return JSON.stringify({ [name]: value });
	if (body instanceof URLSearchParams) {
		const params = new URLSearchParams(body);
		params.set(name, value);
		return params;
	}
	if (typeof body !== 'string') {
		throw new TypeError('Parameter-signed requests support JSON and URL-encoded bodies');
	}
	try {
		const parsed = JSON.parse(body) as unknown;
		if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new TypeError();
		return JSON.stringify({ ...(parsed as Record<string, unknown>), [name]: value });
	} catch (error) {
		if (error instanceof SyntaxError) {
			const params = new URLSearchParams(body);
			params.set(name, value);
			return params;
		}
		throw new TypeError('Parameter-signed JSON bodies must contain an object', { cause: error });
	}
}

export async function applyRequestSigning(
	input: RequestInfo,
	init: RequestInit,
	headers: Headers,
	options: RequestSigningOptions
): Promise<{ input: RequestInfo; body: BodyInit | null | undefined }> {
	if ((options.algo ?? 'hmac-sha256') !== 'hmac-sha256') {
		throw new TypeError('Unsupported request signing algorithm');
	}
	const method = (init.method ?? 'GET').toUpperCase();
	const url = new URL(typeof input === 'string' ? input : input.url);
	let body = init.body;
	const location = options.in ?? 'header';
	const signatureName = options.signature ?? (location === 'header' ? 'x-apicore-signature' : 'signature');
	const timestampName = options.timestamp ?? (location === 'header' ? 'x-apicore-timestamp' : 'timestamp');
	const timestamp = Math.floor(Date.now() / 1000).toString();
	const excludedNames = new Set([signatureName, timestampName]);
	const signature = await signRequest(options.secret, method, url, timestamp, body, excludedNames);
	if (location === 'header') {
		headers.set(timestampName, timestamp);
		headers.set(signatureName, signature);
	} else if (method === 'GET' || method === 'DELETE') {
		url.searchParams.set(timestampName, timestamp);
		url.searchParams.set(signatureName, signature);
	} else {
		body = addParameter(addParameter(body, timestampName, timestamp), signatureName, signature);
		if (!headers.has('content-type') && typeof body === 'string') headers.set('content-type', 'application/json');
	}
	return { input: url.toString(), body };
}

export class HmacSigner extends RequestSigner {
	readonly #options: RequestSigningOptions;

	constructor(options: RequestSigningOptions) {
		super();
		if (!options.secret) throw new TypeError('HmacSigner requires a secret');
		this.#options = { ...options };
	}

	public apply(input: RequestInfo, init: RequestInit, headers: Headers) {
		return applyRequestSigning(input, init, headers, this.#options);
	}
}
