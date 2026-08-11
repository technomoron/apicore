interface HydratableRequest {
	method?: string;
	query?: unknown;
	body?: unknown;
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		return false;
	}
	const proto = Object.getPrototypeOf(value);
	return proto === Object.prototype || proto === null;
}

export function hydrateGetBody(req: HydratableRequest): void {
	if ((req.method ?? '').toUpperCase() !== 'GET') {
		return;
	}

	const query = isPlainObject(req.query) ? req.query : null;
	if (!query || Object.keys(query).length === 0) {
		return;
	}

	const body = isPlainObject(req.body) ? req.body : null;
	if (!body || Object.keys(body).length === 0) {
		req.body = { ...query };
		return;
	}

	// Keep explicit body fields authoritative when both query and body provide the same key.
	req.body = { ...query, ...body };
}
