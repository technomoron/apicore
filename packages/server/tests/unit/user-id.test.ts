import { describe, expect, it } from 'vitest';

import {
	normalizeComparableUserId,
	normalizeNumericUserId,
	normalizeStringUserId
} from '../../src/auth-api/user-id.js';

describe('user id normalization', () => {
	it('normalizes comparable ids to canonical strings', () => {
		expect(normalizeComparableUserId(42)).toBe('42');
		expect(normalizeComparableUserId('0042')).toBe('42');
		expect(normalizeComparableUserId('user-1')).toBe('user-1');
	});

	it('normalizes numeric ids and rejects non-numeric values', () => {
		expect(normalizeNumericUserId(42)).toBe(42);
		expect(normalizeNumericUserId('0042')).toBe(42);
		expect(() => normalizeNumericUserId('user-1')).toThrow(/requires numeric user IDs/);
	});

	it('normalizes string ids and rejects empty values', () => {
		expect(normalizeStringUserId(7)).toBe('7');
		expect(normalizeStringUserId('  user-7  ')).toBe('user-7');
		expect(() => normalizeStringUserId('   ')).toThrow(/Unable to normalise user identifier/);
	});

	it('handles zero as a valid identifier', () => {
		expect(normalizeComparableUserId(0)).toBe('0');
		expect(normalizeComparableUserId('0')).toBe('0');
		expect(normalizeNumericUserId(0)).toBe(0);
	});

	it('rejects empty string', () => {
		expect(() => normalizeComparableUserId('')).toThrow(/Unable to normalise user identifier/);
	});

	it('preserves precision for integers beyond MAX_SAFE_INTEGER', () => {
		const big = String(Number.MAX_SAFE_INTEGER + 1);
		expect(normalizeComparableUserId(big)).toBe(big);
		expect(() => normalizeNumericUserId(big)).toThrow(/safe integer range/);
	});
});
