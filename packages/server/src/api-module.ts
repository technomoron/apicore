import type { ApiErrorParams, ApiRequest } from './apicore-server.js';
import type { RequestSigner } from './base/request-signing.js';
import type { FastifyReply, FastifyRequest, FastifySchema } from 'fastify';

export type ApiHandlerRes<Data = unknown> = [number] | [number, Data] | [number, Data, string];
export type ApiHandlerResult<Data = unknown> = ApiHandlerRes<Data>;
export type ApiHandler<Data = unknown> = (apiReq: ApiRequest) => Promise<ApiHandlerRes<Data>>;
export type ApiAuthType = 'none' | 'maybe' | 'yes' | 'strict' | 'apikey';
export type ApiAuthClass = 'any' | 'admin';
export type ApiRouteSchema = FastifySchema;
export type ApiRouteValidatorContract = unknown;

export interface ApiKey {
	/** Real user identity — who the key belongs to. */
	uid: unknown;
	/** Effective user identity — who the key acts as. When set, the request is treated as impersonation (isImpersonating() === true). */
	euid?: unknown;
	/** Non-secret key handle safe for logs and diagnostics. */
	id?: string;
	/** Opaque application-owned metadata. ApiCore does not enforce policy from this object. */
	meta?: Record<string, unknown>;
}

export interface ApiRouteValidatorContext {
	route: ApiRoute;
	contract: ApiRouteValidatorContract;
	apiReq: ApiRequest;
	request: FastifyRequest;
	reply: FastifyReply;
}

export interface ApiRouteValidatorAdapter {
	name: string;
	supports: (contract: ApiRouteValidatorContract, route: ApiRoute) => boolean;
	validate: (context: ApiRouteValidatorContext) => void | Promise<void>;
	normalizeError?: (error: unknown, context: ApiRouteValidatorContext) => ApiErrorParams | null;
}

export type ApiRoute = {
	method: 'get' | 'post' | 'put' | 'patch' | 'delete';
	path: string;
	handler: ApiHandler;
	auth: {
		type: ApiAuthType;
		req: ApiAuthClass;
	};
	/** Passed through to Fastify and validated by Ajv. */
	schema?: ApiRouteSchema;
	/** Adapter-resolved runtime validator contract for non-Ajv validators. */
	validator?: ApiRouteValidatorContract;
	/** When true/default, body/querystring/params object schemas default to `additionalProperties: false` when omitted. */
	strictProps?: boolean;
	/** Override the module/server request signer, or disable signing for this route. */
	signer?: RequestSigner | false;
};

/** Base class for feature modules mounted into {@link ApiServer}. */
export class ApiModule<T = unknown> {
	private _server?: T;

	/** The server instance this module is mounted on. */
	public get server(): T {
		if (this._server === undefined) {
			throw new Error('ApiModule.server is not set. Mount the module with ApiServer.api(...) before using it.');
		}
		return this._server;
	}

	public set server(value: T) {
		this._server = value;
	}
	/** Route namespace under `apiBasePath`. */
	public namespace: string;
	public mountpath: string = '';
	/** Override the server's default request signer for this module. */
	public signer?: RequestSigner | false;
	public static defaultNamespace = '';

	constructor(opts: { namespace?: string; signer?: RequestSigner | false } = {}) {
		this.namespace = opts.namespace ?? (this.constructor as typeof ApiModule).defaultNamespace ?? '';
		this.signer = opts.signer;
	}

	/** Optional pre-mount configuration validation hook. */
	public checkConfig(): boolean {
		return true;
	}

	/** Return all routes exposed by this module. */
	public defineRoutes(): ApiRoute[] {
		return [];
	}

	/** Optional mount-time hook for modules that need direct server integration. */
	public onMount(): void {
		return;
	}
}
