import { expect, it } from 'vitest';

import { SqlAuthStore } from '../../src/auth-api/sql-auth-store';
import { describeSequelizeSuite, listSequelizeTables } from '../helpers/sequelize-targets.js';

await describeSequelizeSuite('SqlAuthStore table prefixes', ({ getSequelize }) => {
	it('applies global and per-module table prefixes', async () => {
		const sequelize = getSequelize();
		const store = new SqlAuthStore({
			sequelize,
			tablePrefix: 'global_',
			tablePrefixes: {
				token: 'token_',
				oauth: 'oauth_',
				passkey: 'passkey_'
			}
		});

		await store.initialise(true);

		const tables = await listSequelizeTables(sequelize);
		expect(tables).toContain('global_users');
		expect(tables).toContain('token_jwttokens');
		expect(tables).toContain('oauth_oauth_clients');
		expect(tables).toContain('oauth_oauth_codes');
		expect(tables).toContain('passkey_passkey_credentials');
		expect(tables).toContain('passkey_passkey_challenges');

		await store.close();
	});
});
