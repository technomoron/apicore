import assert from 'node:assert/strict';
import test from 'node:test';

import { ApiResponse } from '../../dist/esm/index.js';

test('ApiResponse defaults', () => {
	const r = new ApiResponse();
	assert.equal(r.success, false);
	assert.equal(r.code, 500);
	assert.equal(r.message, '[No Message]');
	assert.equal(r.data, null);
	assert.deepEqual(r.errors, {});
	assert.equal(r.isSuccess(), false);
});

test('ApiResponse constructor normalizes message from Error and supports overrides', () => {
	const r = new ApiResponse({
		success: false,
		code: 400,
		message: new Error('boom'),
		errors: { a: 'b' }
	});
	assert.equal(r.code, 400);
	assert.equal(r.message, 'boom');
	assert.deepEqual(r.errors, { a: 'b' });
});

test('ApiResponse.ok sets success, data, and allows overrides', () => {
	const r = ApiResponse.ok({ x: 1 }, { message: 'yay', code: 201 });
	assert.equal(r.success, true);
	assert.equal(r.code, 201);
	assert.equal(r.message, 'yay');
	assert.deepEqual(r.data, { x: 1 });
	assert.equal(r.isSuccess(), true);
});

test('ApiResponse.error returns same instance if passed an ApiResponse', () => {
	const base = ApiResponse.error('nope', { code: 418 });
	const r = ApiResponse.error(base, { code: 500 });
	assert.equal(r, base);
	assert.equal(r.code, 418);
	assert.equal(r.message, 'nope');
});

test('ApiResponse.error handles unknown message types', () => {
	const r = ApiResponse.error({ not: 'an error' });
	assert.equal(r.success, false);
	assert.equal(r.code, 500);
	assert.equal(typeof r.message, 'string');
});
