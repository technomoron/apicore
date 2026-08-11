import { describe, expect, it } from 'vitest';

import { applyTablePrefix, normalizeTablePrefix } from '../../src/sequelize-utils.js';

describe('sequelize table prefix utilities', () => {
	it('normalizes empty prefixes to undefined', () => {
		expect(normalizeTablePrefix(undefined)).toBeUndefined();
		expect(normalizeTablePrefix('')).toBeUndefined();
		expect(normalizeTablePrefix('   ')).toBeUndefined();
	});

	it('applies trimmed prefixes to table names', () => {
		expect(applyTablePrefix(undefined, 'users')).toBe('users');
		expect(applyTablePrefix('myapp_', 'users')).toBe('myapp_users');
		expect(applyTablePrefix('  myapp_  ', 'users')).toBe('myapp_users');
	});
});
