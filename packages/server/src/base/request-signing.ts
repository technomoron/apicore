import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const REQUEST_SIGNATURE_HEADER = 'x-apicore-signature';
export const REQUEST_TIMESTAMP_HEADER = 'x-apicore-timestamp';
export type RequestSigningAlgorithm = 'hmac-sha256';
export type RequestSigningLocation = 'header' | 'parameter';

export interface RequestSignerOptions {
	in?: RequestSigningLocation;
	signature?: string;
	timestamp?: string;
	maxAge?: number;
}

export interface HmacSignerOptions extends RequestSignerOptions {
	secret: string;
	algo?: RequestSigningAlgorithm;
}

export interface SignableRequest {
	method: string;
	url: string;
	headers: Record<string, string | string[] | undefined>;
	query?: unknown;
	body?: unknown;
}

export class RequestSignatureError extends Error {}

function compareText(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
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

function bodyParameters(body: unknown): Array<[string, string]> {
	if (body === undefined || body === null || body === '') return [];
	let parsed: unknown = body;
	if (Buffer.isBuffer(parsed)) parsed = parsed.toString('utf8');
	if (typeof parsed === 'string') {
		const encoded = parsed;
		try {
			parsed = JSON.parse(encoded) as unknown;
		} catch {
			return Array.from(new URLSearchParams(encoded).entries());
		}
	}
	if (typeof parsed !== 'object' || Array.isArray(parsed)) return [['body', stableValue(parsed)]];
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
	url: string,
	body: unknown,
	excludedNames: ReadonlySet<string> = new Set()
): { query: string; body: string } {
	const parsedUrl = new URL(url, 'http://localhost');
	return {
		query: canonicalParameters([...parsedUrl.searchParams.entries()], excludedNames),
		body: canonicalParameters(bodyParameters(body), excludedNames)
	};
}

export function requestSigningContent(
	method: string,
	url: string,
	timestamp: string,
	body: unknown,
	excludedNames?: ReadonlySet<string>
): string {
	const parsedUrl = new URL(url, 'http://localhost');
	const params = canonicalRequestParameters(url, body, excludedNames);
	return `${method.toUpperCase()}\n${parsedUrl.pathname}\n${timestamp}\n${params.query}\n${params.body}`;
}

export function requestSignature(secret: string, content: string): string {
	return createHmac('sha256', secret).update(content).digest('hex');
}

export function signaturesMatch(expected: string, received: string): boolean {
	if (!/^[a-f\d]{64}$/i.test(received)) return false;
	const expectedBytes = Buffer.from(expected, 'hex');
	const receivedBytes = Buffer.from(received, 'hex');
	return expectedBytes.length === receivedBytes.length && timingSafeEqual(expectedBytes, receivedBytes);
}

/** Base request signer with canonical parameter, transport, and timestamp handling. */
export abstract class RequestSigner {
	public readonly in: RequestSigningLocation;
	public readonly signature: string;
	public readonly timestamp: string;
	public readonly maxAge: number;

	constructor(options: RequestSignerOptions = {}) {
		this.in = options.in ?? 'header';
		this.signature = options.signature ?? (this.in === 'header' ? REQUEST_SIGNATURE_HEADER : 'signature');
		this.timestamp = options.timestamp ?? (this.in === 'header' ? REQUEST_TIMESTAMP_HEADER : 'timestamp');
		if (options.maxAge !== undefined && (!Number.isFinite(options.maxAge) || options.maxAge <= 0)) {
			throw new TypeError('RequestSigner maxAge must be a positive finite number');
		}
		this.maxAge = options.maxAge ?? 300;
	}

	protected abstract createSignature(content: string): string | Promise<string>;

	protected signatureMatches(expected: string, received: string): boolean {
		const expectedHash = createHash('sha256').update(expected).digest();
		const receivedHash = createHash('sha256').update(received).digest();
		return timingSafeEqual(expectedHash, receivedHash);
	}

	/** Override to use a different canonical string while retaining transport and timestamp handling. */
	protected signingContent(method: string, url: string, timestamp: string, body: unknown): string {
		return requestSigningContent(method, url, timestamp, body, new Set([this.signature, this.timestamp]));
	}

	public async sign(
		method: string,
		url: string,
		body: unknown,
		timestamp = Math.floor(Date.now() / 1000).toString()
	) {
		const content = this.signingContent(method, url, timestamp, body);
		return { signature: await this.createSignature(content), timestamp };
	}

	public async apply(
		url: URL,
		method: string,
		body: BodyInit | null | undefined,
		headers: Headers
	): Promise<BodyInit | null | undefined> {
		const signed = await this.sign(method, `${url.pathname}${url.search}`, body);
		if (this.in === 'header') {
			headers.set(this.timestamp, signed.timestamp);
			headers.set(this.signature, signed.signature);
			return body;
		}
		if (method === 'GET' || method === 'DELETE') {
			url.searchParams.set(this.timestamp, signed.timestamp);
			url.searchParams.set(this.signature, signed.signature);
			return body;
		}
		const withTimestamp = this.addParameter(body, this.timestamp, signed.timestamp);
		return this.addParameter(withTimestamp, this.signature, signed.signature);
	}

	public async verify(request: SignableRequest): Promise<void> {
		const credentials = this.takeCredentials(request);
		if (!credentials) throw new RequestSignatureError('Request signature is required');
		if (!/^\d+$/.test(credentials.timestamp)) {
			throw new RequestSignatureError('Request signature timestamp is invalid');
		}
		const timestampSeconds = Number(credentials.timestamp);
		if (!Number.isSafeInteger(timestampSeconds) || Math.abs(Date.now() / 1000 - timestampSeconds) > this.maxAge) {
			throw new RequestSignatureError('Request signature has expired');
		}
		const expected = await this.sign(request.method, request.url, request.body, credentials.timestamp);
		if (!this.signatureMatches(expected.signature, credentials.signature)) {
			throw new RequestSignatureError('Request signature is invalid');
		}
	}

	private header(headers: SignableRequest['headers'], name: string): string | null {
		const value = headers[name.toLowerCase()];
		return Array.isArray(value) ? (value[0] ?? null) : (value ?? null);
	}

	private addParameter(body: BodyInit | null | undefined, name: string, value: string): BodyInit {
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

	private takeParameter(container: unknown, name: string): string | null {
		if (typeof container !== 'object' || container === null || Array.isArray(container)) return null;
		const record = container as Record<string, unknown>;
		const value = record[name];
		delete record[name];
		if (Array.isArray(value)) return typeof value[0] === 'string' ? value[0] : null;
		return typeof value === 'string' ? value : null;
	}

	private takeCredentials(request: SignableRequest): { signature: string; timestamp: string } | null {
		// Always remove credential-named parameters from both locations. These calls
		// are intentional even for header transport so unsigned lookalike fields
		// cannot reach validation or handlers.
		const fromQuery = {
			signature: this.takeParameter(request.query, this.signature),
			timestamp: this.takeParameter(request.query, this.timestamp)
		};
		const fromBody = {
			signature: this.takeParameter(request.body, this.signature),
			timestamp: this.takeParameter(request.body, this.timestamp)
		};
		if (this.in === 'header') {
			const signature = this.header(request.headers, this.signature);
			const timestamp = this.header(request.headers, this.timestamp);
			return signature && timestamp ? { signature, timestamp } : null;
		}
		const credentials = request.method === 'GET' || request.method === 'DELETE' ? fromQuery : fromBody;
		const { signature, timestamp } = credentials;
		return signature && timestamp ? { signature, timestamp } : null;
	}
}

/** HMAC-SHA256 request signer backed by a shared secret. */
export class HmacSigner extends RequestSigner {
	readonly #secret: string;
	public readonly algo: RequestSigningAlgorithm;

	constructor(options: HmacSignerOptions) {
		super(options);
		if (!options.secret) throw new TypeError('HmacSigner requires a secret');
		this.#secret = options.secret;
		this.algo = options.algo ?? 'hmac-sha256';
		if (this.algo !== 'hmac-sha256') throw new TypeError('Unsupported request signing algorithm');
	}

	protected createSignature(content: string): string {
		return requestSignature(this.#secret, content);
	}

	protected override signatureMatches(expected: string, received: string): boolean {
		return signaturesMatch(expected, received);
	}
}
