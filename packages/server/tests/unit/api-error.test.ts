import { describe, it, expect } from 'vitest';

import { ApiError } from '../../src/apicore-server';

describe('ApiError', () => {
	it('normalizes message and defaults', () => {
		const error = new ApiError({
			code: 400,
			message: 'bad stuff',
			data: { foo: 'bar' },
			errors: { field: 'bad' }
		});
		expect(error.code).toBe(400);
		expect(error.message).toBe('bad stuff');
		expect(error.data).toEqual({ foo: 'bar' });
		expect(error.errors).toEqual({ field: 'bad' });
	});

	it('guesses message when message is object', () => {
		const wrapped = new ApiError({ message: new Error('inner failure') });
		expect(wrapped.code).toBe(500);
		expect(wrapped.message).toBe('inner failure');
	});
});
