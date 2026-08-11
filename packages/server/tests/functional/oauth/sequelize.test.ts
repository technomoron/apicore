import { expect, it } from 'vitest';

import { SequelizeOAuthStore } from '../../../src/oauth/sequelize.js';
import { describeSequelizeSuite, listSequelizeTables } from '../../helpers/sequelize-targets.js';

import { runOAuthStoreSuite } from './oauth-store-suite.js';

await describeSequelizeSuite('SequelizeOAuthStore', ({ target, getSequelize }) => {
	runOAuthStoreSuite(target.label, async () => {
		const sequelize = getSequelize();
		const store = new SequelizeOAuthStore({ sequelize });
		await sequelize.sync({ force: true });
		return {
			store,
			cleanup: async () => {}
		};
	});

	it('supports table prefixes', async () => {
		const sequelize = getSequelize();
		new SequelizeOAuthStore({ sequelize, tablePrefix: 'myapp_' });
		await sequelize.sync({ force: true });

		const tables = await listSequelizeTables(sequelize);
		expect(tables).toContain('myapp_oauth_clients');
		expect(tables).toContain('myapp_oauth_codes');
	});
});
