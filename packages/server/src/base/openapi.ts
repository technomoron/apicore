import type { ApiAuthClass, ApiAuthType } from '../api-module.js';

type OpenApiObject = Record<string, unknown>;
type OpenApiAuth = { type: ApiAuthType; req?: ApiAuthClass };

interface PathPrefixTarget {
	path: string;
	auth?: OpenApiAuth;
}

interface TransformedPathTarget {
	path: string;
	auth?: OpenApiAuth;
}

const operationMethods = new Set(['delete', 'get', 'head', 'options', 'patch', 'post', 'put', 'trace']);
const authenticatedSecurity: Array<Record<string, never[]>> = [
	{ accessTokenBearer: [] },
	{ accessTokenCookie: [] },
	{ apiKeyBearer: [] }
];

function isObject(value: unknown): value is OpenApiObject {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizePath(value: string): string {
	const withLeadingSlash = value.startsWith('/') ? value : `/${value}`;
	const normalized = withLeadingSlash.replace(/\/+/g, '/').replace(/\/+$/, '');
	return normalized || '/';
}

function routePath(value: string): string {
	return normalizePath(value).replace(/:([A-Za-z0-9_]+)/g, '{$1}');
}

function routeKey(method: string, path: string): string {
	return `${method.toLowerCase()} ${routePath(path)}`;
}

function matchesPrefix(path: string, prefix: string): boolean {
	return path === prefix || path.startsWith(`${prefix}/`);
}

function replacePrefix(path: string, source: string, target: string): string {
	const suffix = path.slice(source.length);
	return normalizePath(`${target === '/' ? '' : target}${suffix}`);
}

function authLabel(type: ApiAuthType): 'none' | 'optional' | 'required' | 'strict' {
	switch (type) {
		case 'none':
			return 'none';
		case 'maybe':
			return 'optional';
		case 'strict':
			return 'strict';
		default:
			return 'required';
	}
}

function authSecurity(type: ApiAuthType): Array<Record<string, never[]>> {
	if (type === 'none') {
		return [];
	}
	if (type === 'apikey') {
		return [{ apiKeyBearer: [] }];
	}
	const security = authenticatedSecurity.map((entry) => ({ ...entry }));
	return type === 'maybe' ? [{}, ...security] : security;
}

function applyAuth(operation: OpenApiObject, auth: OpenApiAuth): void {
	const label = authLabel(auth.type);
	const description = typeof operation.description === 'string' ? operation.description : '';
	const detail = description.replace(/^Auth: (?:none|optional|required|strict)\.?\s*/i, '');
	operation.description = `Auth: ${label}.${detail ? ` ${detail}` : ''}`;
	operation.security = authSecurity(auth.type);
}

function collectSchemaRefs(value: unknown, refs: Set<string>): void {
	if (Array.isArray(value)) {
		for (const entry of value) {
			collectSchemaRefs(entry, refs);
		}
		return;
	}
	if (!isObject(value)) {
		return;
	}
	const reference = value.$ref;
	if (typeof reference === 'string' && reference.startsWith('#/components/schemas/')) {
		refs.add(reference.slice('#/components/schemas/'.length));
	}
	for (const entry of Object.values(value)) {
		collectSchemaRefs(entry, refs);
	}
}

function reachableSchemas(paths: unknown, schemas: OpenApiObject): Set<string> {
	const reachable = new Set<string>();
	const expanded = new Set<string>();
	collectSchemaRefs(paths, reachable);
	const pending = [...reachable];
	while (pending.length > 0) {
		const name = pending.pop() as string;
		if (expanded.has(name)) {
			continue;
		}
		expanded.add(name);
		const discovered = new Set<string>();
		collectSchemaRefs(schemas[name], discovered);
		for (const reference of discovered) {
			if (!reachable.has(reference)) {
				reachable.add(reference);
				pending.push(reference);
			}
		}
	}
	return reachable;
}

function pruneSchemas(document: OpenApiObject): void {
	const components = isObject(document.components) ? document.components : null;
	const schemas = components && isObject(components.schemas) ? components.schemas : null;
	if (!schemas) {
		return;
	}
	const refs = reachableSchemas(document.paths, schemas);
	for (const name of Object.keys(schemas)) {
		if (!refs.has(name)) {
			delete schemas[name];
		}
	}
}

function addOperationTags(pathItem: OpenApiObject, used: Set<string>): void {
	for (const [method, operation] of Object.entries(pathItem)) {
		if (!operationMethods.has(method) || !isObject(operation) || !Array.isArray(operation.tags)) {
			continue;
		}
		for (const tag of operation.tags) {
			if (typeof tag === 'string') {
				used.add(tag);
			}
		}
	}
}

function usedTags(paths: OpenApiObject): Set<string> {
	const used = new Set<string>();
	for (const pathItem of Object.values(paths)) {
		if (isObject(pathItem)) {
			addOperationTags(pathItem, used);
		}
	}
	return used;
}

function pruneTags(document: OpenApiObject): void {
	if (!Array.isArray(document.tags) || !isObject(document.paths)) {
		return;
	}
	const used = usedTags(document.paths);
	document.tags = document.tags.filter((tag) => isObject(tag) && typeof tag.name === 'string' && used.has(tag.name));
}

function pathTargets(sourcePath: string, prefixes: Array<[string, PathPrefixTarget[]]>): TransformedPathTarget[] {
	const matched = prefixes.find(([prefix]) => matchesPrefix(sourcePath, prefix));
	if (!matched) {
		return [{ path: normalizePath(sourcePath) }];
	}
	return matched[1].map((target) => ({
		path: replacePrefix(sourcePath, matched[0], target.path),
		auth: target.auth
	}));
}

function applyRequestSigningSecurity(operation: OpenApiObject): void {
	const security = Array.isArray(operation.security) ? operation.security : [];
	operation.security =
		security.length > 0
			? security.map((requirement) =>
					isObject(requirement) ? { ...requirement, requestSignature: [] } : requirement
				)
			: [{ requestSignature: [] }];
}

function transformOperation(value: OpenApiObject, method: string, auth?: OpenApiAuth, signed = false): OpenApiObject {
	const operation = JSON.parse(JSON.stringify(value)) as OpenApiObject;
	if (auth && method !== 'options') {
		applyAuth(operation, auth);
	}
	if (signed && method !== 'options') {
		applyRequestSigningSecurity(operation);
	}
	return operation;
}

function transformPathItem(
	pathItem: OpenApiObject,
	target: TransformedPathTarget,
	routes: Set<string>,
	signedRoutes: Set<string>
): OpenApiObject | null {
	const transformed: OpenApiObject = {};
	let operations = 0;
	for (const [method, value] of Object.entries(pathItem)) {
		if (!operationMethods.has(method)) {
			transformed[method] = value;
			continue;
		}
		if (!routes.has(routeKey(method, target.path)) || !isObject(value)) {
			continue;
		}
		transformed[method] = transformOperation(
			value,
			method,
			target.auth,
			signedRoutes.has(routeKey(method, target.path))
		);
		operations += 1;
	}
	return operations > 0 ? transformed : null;
}

export class RuntimeOpenApiDocument {
	private readonly routes = new Set<string>();
	private readonly signedRoutes = new Set<string>();
	private readonly prefixes = new Map<string, PathPrefixTarget[]>();

	public registerRoute(method: string | string[], url: string, signed = false): void {
		for (const value of Array.isArray(method) ? method : [method]) {
			const key = routeKey(value, url);
			this.routes.add(key);
			if (signed) this.signedRoutes.add(key);
		}
	}

	public registerPathPrefix(source: string, target: string, auth?: OpenApiAuth): void {
		const normalizedSource = normalizePath(source);
		const normalizedTarget = normalizePath(target);
		const targets = this.prefixes.get(normalizedSource) ?? [];
		if (!targets.some((entry) => entry.path === normalizedTarget)) {
			targets.push({ path: normalizedTarget, auth });
			this.prefixes.set(normalizedSource, targets);
		}
	}

	public build(source: OpenApiObject): OpenApiObject {
		const document = JSON.parse(JSON.stringify(source)) as OpenApiObject;
		const sourcePaths = isObject(document.paths) ? document.paths : {};
		const paths: OpenApiObject = {};
		const prefixes = [...this.prefixes.entries()].sort(([left], [right]) => right.length - left.length);

		for (const [sourcePath, pathItem] of Object.entries(sourcePaths)) {
			if (!isObject(pathItem)) {
				continue;
			}
			for (const target of pathTargets(sourcePath, prefixes)) {
				const transformed = transformPathItem(pathItem, target, this.routes, this.signedRoutes);
				if (transformed) {
					paths[target.path] = transformed;
				}
			}
		}

		document.paths = paths;
		pruneSchemas(document);
		pruneTags(document);
		return document;
	}
}
