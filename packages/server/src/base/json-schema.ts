import type { FastifySchema } from 'fastify';

export type JsonSchema = Record<string, unknown>;

export const emptyObjectSchema: JsonSchema = {
	type: 'object',
	properties: {},
	additionalProperties: false
};

function isJsonSchema(value: unknown): value is JsonSchema {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function looksLikeObjectSchema(schema: JsonSchema): boolean {
	return (
		schema.type === 'object' ||
		'properties' in schema ||
		'required' in schema ||
		'patternProperties' in schema ||
		'additionalProperties' in schema
	);
}

export function applyRouteSchemaDefaults(
	schema: FastifySchema | undefined,
	options: { strictProps?: boolean } = {}
): FastifySchema | undefined {
	if (!schema) {
		return schema;
	}

	const strictProps = options.strictProps ?? true;
	let changed = false;
	const nextSchema = { ...schema } as FastifySchema & Record<string, unknown>;

	for (const key of ['body', 'querystring', 'params'] as const) {
		const candidate = nextSchema[key];
		if (!isJsonSchema(candidate) || !looksLikeObjectSchema(candidate)) {
			continue;
		}
		if (Object.prototype.hasOwnProperty.call(candidate, 'additionalProperties')) {
			continue;
		}
		nextSchema[key] = {
			...candidate,
			additionalProperties: !strictProps
		};
		changed = true;
	}

	return changed ? nextSchema : schema;
}
