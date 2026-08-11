import { expect, it } from 'vitest';

import { SequelizeUserStore } from '../../../src/user/sequelize.js';
import { describeSequelizeSuite, listSequelizeTables } from '../../helpers/sequelize-targets.js';

import { runUserStoreSuite } from './user-store-suite.js';

await describeSequelizeSuite('SequelizeUserStore', ({ target, getSequelize }) => {
	runUserStoreSuite(target.label, async () => {
		const sequelize = getSequelize();
		const store = new SequelizeUserStore({ sequelize });
		await sequelize.sync({ force: true });
		return {
			store,
			cleanup: async () => {}
		};
	});

	it('supports table prefixes', async () => {
		const sequelize = getSequelize();
		new SequelizeUserStore({ sequelize, tablePrefix: 'myapp_' });
		await sequelize.sync({ force: true });

		const tables = await listSequelizeTables(sequelize);
		expect(tables).toContain('myapp_users');
	});
});
