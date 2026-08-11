import request from 'supertest';
import { describe, expect, it } from 'vitest';

import { ApiError, ApiModule, type ApiRoute, type ApiRouteValidatorAdapter } from '../../src/apicore-server';
import { createServer } from '../helpers/test-server';

type FakeContract = {
	kind: 'fake-body';
	requiredField: string;
};

function isFakeContract(value: unknown): value is FakeContract {
	return Boolean(
		value &&
		typeof value === 'object' &&
		!Array.isArray(value) &&
		(value as { kind?: unknown }).kind === 'fake-body' &&
		typeof (value as { requiredField?: unknown }).requiredField === 'string'
	);
}

const fakeBodyAdapter: ApiRouteValidatorAdapter = {
	name: 'fake-body',
	supports: (contract) => isFakeContract(contract),
	validate: ({ contract, apiReq }) => {
		if (!isFakeContract(contract)) {
			throw new Error('Unexpected fake contract');
		}
		const body =
			apiReq.req.body && typeof apiReq.req.body === 'object' && !Array.isArray(apiReq.req.body)
				? (apiReq.req.body as Record<string, unknown>)
				: {};
		const value = body[contract.requiredField];
		if (typeof value !== 'string' || value.trim().length === 0) {
			throw {
				issues: [
					{
						field: contract.requiredField,
						message: 'must be a non-empty string'
					}
				]
			};
		}
	},
	normalizeError: (error) => {
		if (!error || typeof error !== 'object' || !Array.isArray((error as { issues?: unknown[] }).issues)) {
			return null;
		}
		const issues = (error as { issues: Array<{ field?: unknown; message?: unknown }> }).issues;
		const fieldErrors: Record<string, string> = {};
		for (const issue of issues) {
			const field = typeof issue.field === 'string' && issue.field.length > 0 ? issue.field : 'body';
			fieldErrors[field] = typeof issue.message === 'string' ? issue.message : 'Invalid value';
		}
		return {
			code: 400,
			message: 'Validation failed',
			errors: fieldErrors
		};
	}
};

class ValidatedModule extends ApiModule {
	public static override defaultNamespace = '/validated';

	public override defineRoutes(): ApiRoute[] {
		return [
			{
				method: 'post',
				path: '/custom',
				auth: { type: 'none', req: 'any' },
				validator: {
					kind: 'fake-body',
					requiredField: 'name'
				} satisfies FakeContract,
				handler: async ({ req }) => [200, req.body ?? null]
			}
		];
	}
}

class ApiErrorModule extends ApiModule {
	public static override defaultNamespace = '/validated';

	public override defineRoutes(): ApiRoute[] {
		return [
			{
				method: 'post',
				path: '/api-error',
				auth: { type: 'none', req: 'any' },
				validator: { kind: 'api-error' },
				handler: async () => [200, { ok: true }]
			}
		];
	}
}

const apiErrorAdapter: ApiRouteValidatorAdapter = {
	name: 'api-error-adapter',
	supports: (contract) =>
		Boolean(
			contract &&
			typeof contract === 'object' &&
			!Array.isArray(contract) &&
			(contract as { kind?: unknown }).kind === 'api-error'
		),
	validate: () => {
		throw new ApiError({
			code: 422,
			message: 'Adapter rejected request',
			errors: { field: 'bad input' }
		});
	}
};

describe('Validator adapters', () => {
	it('normalizes adapter validation failures into the ApiError envelope', async () => {
		const server = createServer();
		server.addValidatorAdapter(fakeBodyAdapter);
		server.api(new ValidatedModule());

		const response = await request(server.app).post('/api/validated/custom').send({});

		expect(response.status).toBe(400);
		expect(response.body).toEqual({
			success: false,
			code: 400,
			message: 'Validation failed',
			data: null,
			errors: { name: 'must be a non-empty string' }
		});
	});

	it('passes through ApiError thrown directly by an adapter', async () => {
		const server = createServer();
		server.addValidatorAdapter(apiErrorAdapter);
		server.api(new ApiErrorModule());

		const response = await request(server.app).post('/api/validated/api-error').send({});

		expect(response.status).toBe(422);
		expect(response.body).toEqual({
			success: false,
			code: 422,
			message: 'Adapter rejected request',
			data: null,
			errors: { field: 'bad input' }
		});
	});

	it('fails route registration when no validator adapter matches a route contract', async () => {
		const server = createServer();

		expect(() => server.api(new ValidatedModule())).toThrow('No validator adapter matched POST /custom');
	});

	it('fails route registration when multiple validator adapters match a route contract', async () => {
		const server = createServer();
		server.addValidatorAdapter(fakeBodyAdapter);
		server.addValidatorAdapter({
			name: 'fake-body-copy',
			supports: fakeBodyAdapter.supports,
			validate: fakeBodyAdapter.validate,
			normalizeError: fakeBodyAdapter.normalizeError
		});

		expect(() => server.api(new ValidatedModule())).toThrow(
			'Multiple validator adapters matched POST /custom: fake-body, fake-body-copy'
		);
	});
});
