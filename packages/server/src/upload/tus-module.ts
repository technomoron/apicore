import { ApiError, ApiModule, type ApiAuthClass, type ApiAuthType, type ApiServer } from '../apicore-server.js';
import { emptyObjectSchema, type JsonSchema } from '../base/json-schema.js';

import { TusUploadCapacityError, TusUploadExceedsLengthError, TusUploadOffsetError } from './errors.js';
import { FileTusUploadStore } from './file.js';

import type { TusCreateUploadInput, TusMetadata, TusUploadRecord, TusUploadStore } from './types.js';
import type { FastifyReply, FastifyRequest } from 'fastify';

const TUS_VERSION = '1.0.0';

const tusResumableHeadersSchema: JsonSchema = {
	type: 'object',
	required: ['tus-resumable'],
	properties: {
		'tus-resumable': { type: 'string', const: TUS_VERSION }
	},
	additionalProperties: true
};

const createUploadHeadersSchema: JsonSchema = {
	type: 'object',
	required: ['tus-resumable', 'upload-length'],
	properties: {
		'tus-resumable': { type: 'string', const: TUS_VERSION },
		'upload-length': { type: 'string', pattern: '^[1-9]\\d*$' },
		'upload-metadata': { type: 'string' }
	},
	additionalProperties: true
};

const uploadOffsetHeadersSchema: JsonSchema = {
	type: 'object',
	required: ['tus-resumable', 'upload-offset', 'content-type'],
	properties: {
		'tus-resumable': { type: 'string', const: TUS_VERSION },
		'upload-offset': { type: 'string', pattern: '^(0|[1-9]\\d*)$' },
		'content-type': { type: 'string', const: 'application/offset+octet-stream' }
	},
	additionalProperties: true
};

const uploadIdParamsSchema: JsonSchema = {
	type: 'object',
	required: ['uploadId'],
	properties: {
		uploadId: { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' }
	},
	additionalProperties: false
};

const uploadIdRouteSchema = {
	headers: tusResumableHeadersSchema,
	params: uploadIdParamsSchema,
	querystring: emptyObjectSchema
};

function parseNonNegativeInt(raw: unknown, headerName: string): number {
	const value = Array.isArray(raw) ? raw[0] : raw;
	const parsed = Number.parseInt(String(value ?? ''), 10);
	if (!Number.isFinite(parsed) || parsed < 0) {
		throw new ApiError({
			code: 400,
			message: `Missing or invalid ${headerName} header`
		});
	}
	return parsed;
}

function parseUploadLength(raw: unknown): number {
	return parseNonNegativeInt(raw, 'Upload-Length');
}

function parseOffset(raw: unknown): number {
	return parseNonNegativeInt(raw, 'Upload-Offset');
}

function decodeMetadata(raw: unknown): TusMetadata {
	const source = Array.isArray(raw) ? raw[0] : raw;
	const input = String(source ?? '').trim();
	if (!input) {
		return {};
	}
	const out: TusMetadata = {};
	for (const pair of input.split(',')) {
		const trimmed = pair.trim();
		if (!trimmed) {
			continue;
		}
		const [key, encoded = ''] = trimmed.split(' ');
		if (!key) {
			continue;
		}
		try {
			out[key] = Buffer.from(encoded, 'base64').toString('utf8');
		} catch {
			out[key] = '';
		}
	}
	return out;
}

async function readChunk(request: FastifyRequest, maxBytes: number): Promise<Buffer> {
	if (Buffer.isBuffer(request.body)) {
		return request.body;
	}
	if (typeof request.body === 'string') {
		return Buffer.from(request.body);
	}
	// Fastify only sets request.body when the Content-Type parser fires.
	// Fall back to reading the raw stream, but enforce the same size cap to
	// prevent bodyLimit from being bypassed by omitting the Content-Type header.
	const parts: Buffer[] = [];
	let total = 0;
	for await (const chunk of request.raw) {
		const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
		total += buf.length;
		if (total > maxBytes) {
			throw new ApiError({
				code: 413,
				message: 'Upload chunk exceeds maximum chunk size'
			});
		}
		parts.push(buf);
	}
	return Buffer.concat(parts);
}

function setTusHeaders(reply: FastifyReply, uploadMaxBytes: number, supportsTermination = false): void {
	reply.header('Tus-Resumable', TUS_VERSION);
	reply.header('Tus-Version', TUS_VERSION);
	reply.header('Tus-Max-Size', String(uploadMaxBytes));
	reply.header('Tus-Extension', supportsTermination ? 'creation,expiration,termination' : 'creation,expiration');
}

function toLocation(basePath: string, uploadId: string): string {
	const normalized = basePath.endsWith('/') ? basePath.slice(0, -1) : basePath;
	return `${normalized}/${uploadId}`;
}

export interface TusUploadModuleOptions {
	basePath?: string;
	/**
	 * Authentication requirement for all TUS upload routes. Public access must
	 * be selected explicitly with `{ type: 'none', req: 'any' }`.
	 */
	auth: { type: ApiAuthType; req?: ApiAuthClass };
	store?: TusUploadStore;
	/** Directory for the default file store. Defaults to `uploadPath/tus`. */
	storagePath?: string;
	chunkMaxBytes?: number;
	/** Maximum allowed value for Upload-Length. Defaults to ApiServer.uploadMax. */
	uploadMaxBytes?: number;
	/**
	 * Validate the declared upload size and metadata before a file is created.
	 * Throw ApiError to reject the upload. Metadata such as `filetype` is
	 * client-declared and should be verified from the completed file as well.
	 */
	validateUpload?: (upload: Readonly<TusCreateUploadInput>) => Promise<void> | void;
	onUploadComplete?: (upload: TusUploadRecord) => Promise<void> | void;
}

export class TusUploadModule extends ApiModule<ApiServer> {
	private static readonly AUTH_FAILED_SENTINEL = '\0auth-failed';

	private readonly basePath: string;
	private readonly chunkMaxBytes: number;
	private uploadMaxBytes = 0;
	private store!: TusUploadStore;
	private readonly configuredStore?: TusUploadStore;
	private readonly storagePath?: string;
	private readonly configuredUploadMaxBytes?: number;
	private readonly auth: { type: ApiAuthType; req?: ApiAuthClass };
	private readonly validateUpload?: (upload: Readonly<TusCreateUploadInput>) => Promise<void> | void;
	private readonly onUploadComplete?: (upload: TusUploadRecord) => Promise<void> | void;

	constructor(options: TusUploadModuleOptions) {
		super({ namespace: '' });
		if (!options?.auth) {
			throw new Error(
				'TusUploadModule requires an explicit auth option. Use { type: "none", req: "any" } for public uploads.'
			);
		}
		if (options.store && options.storagePath) {
			throw new Error('TusUploadModule storagePath cannot be combined with a custom store');
		}
		const rawPath = options.basePath?.trim() || '/api/v1/upload';
		this.basePath = rawPath.startsWith('/') ? rawPath : `/${rawPath}`;
		this.chunkMaxBytes = options.chunkMaxBytes ?? 5 * 1024 * 1024;
		this.configuredUploadMaxBytes = options.uploadMaxBytes;
		this.configuredStore = options.store;
		this.storagePath = options.storagePath;
		this.auth = options.auth;
		this.validateUpload = options.validateUpload;
		this.onUploadComplete = options.onUploadComplete;
	}

	public override onMount(): void {
		this.uploadMaxBytes = this.configuredUploadMaxBytes ?? this.server.config.uploadMax;
		this.store =
			this.configuredStore ?? new FileTusUploadStore(this.storagePath ?? this.server.getUploadPath('tus'));
		this.server.registerTusUploadStore(this.store);
		this.server.registerOpenApiPathPrefix('/api/v1/upload', this.basePath, this.auth);
		this.installTusRoutes();
	}

	/** Authenticate the request and return its user ID when one is available. */
	private async checkAuth(request: FastifyRequest, reply: FastifyReply): Promise<string | null> {
		try {
			const apiReq = await this.server.resolveRequest(request, reply, this.auth);
			return apiReq.tokenData?.uid != null ? String(apiReq.tokenData.uid) : null;
		} catch (error) {
			const code = error instanceof ApiError ? error.code : 401;
			const message = error instanceof ApiError ? error.message : 'Unauthorized';
			reply.code(code).send({
				success: false,
				code,
				message,
				data: null,
				errors: {}
			});
			return TusUploadModule.AUTH_FAILED_SENTINEL;
		}
	}

	private authFailed(result: string | null): boolean {
		return result === TusUploadModule.AUTH_FAILED_SENTINEL;
	}

	private sendJsonError(reply: FastifyReply, code: number, message: string): void {
		reply.code(code).send({
			success: false,
			code,
			message,
			data: null,
			errors: {}
		});
	}

	private verifyOwnership(upload: TusUploadRecord, authUserId: string | null, reply: FastifyReply): boolean {
		if (upload.userId && upload.userId !== authUserId) {
			this.sendJsonError(reply, 403, 'Upload belongs to another user');
			return false;
		}
		return true;
	}

	private async loadOwnedUpload(
		request: FastifyRequest,
		reply: FastifyReply,
		authUserId: string | null
	): Promise<{ uploadId: string; upload: TusUploadRecord } | null> {
		const uploadId = String((request.params as { uploadId?: string }).uploadId ?? '');
		const upload = await this.store.getUpload(uploadId);
		if (!upload) {
			reply.code(404).send();
			return null;
		}
		if (
			!upload.completedAt &&
			upload.updatedAt.getTime() + this.server.config.uploadOrphanExpirySeconds * 1000 <= Date.now()
		) {
			await this.store.deleteUpload?.(uploadId);
			reply.code(410).send();
			return null;
		}
		if (!this.verifyOwnership(upload, authUserId, reply)) {
			return null;
		}
		return { uploadId, upload };
	}

	private async loadRouteUpload(
		request: FastifyRequest,
		reply: FastifyReply,
		hasTermination: boolean
	): Promise<{ uploadId: string; upload: TusUploadRecord } | null> {
		const authUserId = await this.checkAuth(request, reply);
		if (this.authFailed(authUserId)) return null;
		setTusHeaders(reply, this.uploadMaxBytes, hasTermination);
		return this.loadOwnedUpload(request, reply, authUserId);
	}

	private setUploadExpiryHeader(reply: FastifyReply, upload: TusUploadRecord): void {
		if (upload.completedAt) {
			return;
		}
		const expiresAt = new Date(upload.updatedAt.getTime() + this.server.config.uploadOrphanExpirySeconds * 1000);
		reply.header('Upload-Expires', expiresAt.toUTCString());
	}

	private async prepareStoreSpace(expectedBytes: number): Promise<void> {
		if (this.store.storagePath) {
			await this.server.prepareUploadDirectory(this.store.storagePath, expectedBytes);
		}
	}

	private installTusContentParser(): void {
		try {
			this.server.fastify.addContentTypeParser(
				'application/offset+octet-stream',
				{ parseAs: 'buffer' },
				(_req, body, done) => {
					done(null, body);
				}
			);
		} catch (error) {
			// Parser may already be present when mounting multiple upload modules.
			const message = error instanceof Error ? error.message : '';
			if (!message.includes('already registered') && !message.includes('already exists')) {
				throw error;
			}
		}
	}

	private installTusRoutes(): void {
		const hasTermination = typeof this.store.deleteUpload === 'function';
		this.installTusContentParser();
		this.installOptionsRoute(hasTermination);
		this.installCreateRoute(hasTermination);
		this.installHeadRoute(hasTermination);
		this.installPatchRoute(hasTermination);
		this.installDeleteRoute(hasTermination);
	}

	private installOptionsRoute(hasTermination: boolean): void {
		this.server.fastify.options(
			this.basePath,
			{ schema: { querystring: emptyObjectSchema } },
			async (_request, reply) => {
				setTusHeaders(reply, this.uploadMaxBytes, hasTermination);
				reply.code(204).send();
			}
		);
	}

	private installCreateRoute(hasTermination: boolean): void {
		this.server.fastify.post(
			this.basePath,
			{
				schema: {
					headers: createUploadHeadersSchema,
					querystring: emptyObjectSchema
				}
			},
			(request, reply) => this.createUpload(request, reply, hasTermination)
		);
	}

	private async createUpload(request: FastifyRequest, reply: FastifyReply, hasTermination: boolean): Promise<void> {
		const authUserId = await this.checkAuth(request, reply);
		if (this.authFailed(authUserId)) return;
		setTusHeaders(reply, this.uploadMaxBytes, hasTermination);
		const length = parseUploadLength(request.headers['upload-length']);
		if (length <= 0) {
			this.sendJsonError(reply, 400, 'Upload-Length must be greater than zero');
			return;
		}
		if (length > this.uploadMaxBytes) {
			this.sendJsonError(
				reply,
				413,
				`Upload-Length exceeds the maximum allowed size of ${this.uploadMaxBytes} bytes`
			);
			return;
		}
		const createInput: TusCreateUploadInput = {
			length,
			metadata: decodeMetadata(request.headers['upload-metadata']),
			userId: authUserId ?? undefined
		};
		await this.validateUpload?.(createInput);
		await this.prepareStoreSpace(length);
		let created: TusUploadRecord;
		try {
			created = await this.store.createUpload(createInput);
		} catch (error) {
			if (error instanceof TusUploadCapacityError) {
				this.sendJsonError(reply, 507, error.message);
				return;
			}
			throw error;
		}
		reply.header('Location', toLocation(this.basePath, created.id));
		reply.header('Upload-Offset', String(created.offset));
		this.setUploadExpiryHeader(reply, created);
		reply.code(201).send();
	}

	private installHeadRoute(hasTermination: boolean): void {
		this.server.fastify.head(
			`${this.basePath}/:uploadId`,
			{
				schema: uploadIdRouteSchema
			},
			(request, reply) => this.inspectUpload(request, reply, hasTermination)
		);
	}

	private async inspectUpload(request: FastifyRequest, reply: FastifyReply, hasTermination: boolean): Promise<void> {
		const found = await this.loadRouteUpload(request, reply, hasTermination);
		if (!found) return;
		const { upload } = found;
		reply.header('Upload-Offset', String(upload.offset));
		reply.header('Upload-Length', String(upload.length));
		this.setUploadExpiryHeader(reply, upload);
		reply.code(200).send();
	}

	private installPatchRoute(hasTermination: boolean): void {
		this.server.fastify.patch(
			`${this.basePath}/:uploadId`,
			{
				bodyLimit: this.chunkMaxBytes,
				schema: {
					headers: uploadOffsetHeadersSchema,
					params: uploadIdParamsSchema,
					querystring: emptyObjectSchema
				}
			},
			(request, reply) => this.appendUpload(request, reply, hasTermination)
		);
	}

	private async appendUpload(request: FastifyRequest, reply: FastifyReply, hasTermination: boolean): Promise<void> {
		const found = await this.loadRouteUpload(request, reply, hasTermination);
		if (!found) return;
		const { uploadId, upload } = found;
		const offset = parseOffset(request.headers['upload-offset']);
		if (offset !== upload.offset) {
			reply.header('Upload-Offset', String(upload.offset));
			reply.code(409).send();
			return;
		}
		const chunk = await readChunk(request, this.chunkMaxBytes);
		await this.prepareStoreSpace(chunk.length);
		try {
			const updated = await this.store.appendUpload({ uploadId, offset, chunk });
			reply.header('Upload-Offset', String(updated.offset));
			this.setUploadExpiryHeader(reply, updated);
			await this.notifyUploadComplete(upload, updated);
			reply.code(204).send();
		} catch (error) {
			this.handleAppendError(error, reply);
		}
	}

	private async notifyUploadComplete(previous: TusUploadRecord, updated: TusUploadRecord): Promise<void> {
		if (previous.completedAt || !updated.completedAt || !this.onUploadComplete) {
			return;
		}
		try {
			await this.onUploadComplete(updated);
		} catch (error) {
			console.error('[TusUploadModule] onUploadComplete callback failed', error);
		}
	}

	private handleAppendError(error: unknown, reply: FastifyReply): never | void {
		if (error instanceof TusUploadOffsetError) {
			reply.header('Upload-Offset', String(error.currentOffset));
			reply.code(409).send();
			return;
		}
		if (error instanceof TusUploadExceedsLengthError) {
			this.sendJsonError(reply, 413, 'Upload chunk exceeds declared upload length');
			return;
		}
		throw error;
	}

	private installDeleteRoute(hasTermination: boolean): void {
		this.server.fastify.delete(
			`${this.basePath}/:uploadId`,
			{
				schema: uploadIdRouteSchema
			},
			(request, reply) => this.deleteUpload(request, reply, hasTermination)
		);
	}

	private async deleteUpload(request: FastifyRequest, reply: FastifyReply, hasTermination: boolean): Promise<void> {
		const authUserId = await this.checkAuth(request, reply);
		if (this.authFailed(authUserId)) return;
		setTusHeaders(reply, this.uploadMaxBytes, hasTermination);
		if (!this.store.deleteUpload) {
			reply.header('Allow', 'OPTIONS, POST, HEAD, PATCH');
			reply.code(405).send();
			return;
		}
		const found = await this.loadOwnedUpload(request, reply, authUserId);
		if (!found) return;
		const deleted = await this.store.deleteUpload(found.uploadId);
		reply.code(deleted ? 204 : 404).send();
	}
}
