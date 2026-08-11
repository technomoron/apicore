import { test, expect } from 'vitest';

import { ApiResponse } from '../../src/index.js';

test('ApiResponse defaults', () => {
	const r = new ApiResponse();
	expect(r.success).toBe(false);
	expect(r.code).toBe(500);
	expect(r.message).toBe('[No Message]');
	expect(r.data).toBe(null);
	expect(r.errors).toStrictEqual({});
	expect(r.isSuccess()).toBe(false);
});

test('ApiResponse constructor normalizes message from Error and supports overrides', () => {
	const r = new ApiResponse({
		success: false,
		code: 400,
		message: new Error('boom') as unknown as string,
		errors: { a: 'b' }
	});
	expect(r.code).toBe(400);
	expect(r.message).toBe('boom');
	expect(r.errors).toStrictEqual({ a: 'b' });
});

test('ApiResponse.ok sets success, data, and allows overrides', () => {
	const r = ApiResponse.ok({ x: 1 }, { message: 'yay', code: 201 });
	expect(r.success).toBe(true);
	expect(r.code).toBe(201);
	expect(r.message).toBe('yay');
	expect(r.data).toStrictEqual({ x: 1 });
	expect(r.isSuccess()).toBe(true);
});

test('ApiResponse.error returns same instance if passed an ApiResponse', () => {
	const base = ApiResponse.error('nope', { code: 418 });
	const r = ApiResponse.error(base, { code: 500 });
	expect(r).toBe(base);
	expect(r.code).toBe(418);
	expect(r.message).toBe('nope');
});

test('ApiResponse.error handles unknown message types', () => {
	const r = ApiResponse.error({ not: 'an error' });
	expect(r.success).toBe(false);
	expect(r.code).toBe(500);
	expect(typeof r.message).toBe('string');
});
