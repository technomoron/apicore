import { expect, it } from 'vitest';

import { SequelizeTokenStore } from '../../../src/token/sequelize.js';
import { describeSequelizeSuite, listSequelizeTables } from '../../helpers/sequelize-targets.js';

import { runTokenStoreSuite } from './token-store-suite.js';

await describeSequelizeSuite('SequelizeTokenStore', ({ target, getSequelize }) => {
	runTokenStoreSuite(target.label, async () => {
		const sequelize = getSequelize();
		const store = new SequelizeTokenStore({ sequelize });
		await sequelize.sync({ force: true });

		return {
			store,
			cleanup: async () => {}
		};
	});

	it('supports table prefixes', async () => {
		const sequelize = getSequelize();
		new SequelizeTokenStore({ sequelize, tablePrefix: 'myapp_' });
		await sequelize.sync({ force: true });

		const tables = await listSequelizeTables(sequelize);
		expect(tables).toContain('myapp_jwttokens');
	});

	it('uses unbounded text columns for access and refresh JWT values', async () => {
		const sequelize = getSequelize();
		new SequelizeTokenStore({ sequelize });
		await sequelize.sync({ force: true });

		const columns = await sequelize.getQueryInterface().describeTable('jwttokens');
		expect(String(columns.access?.type ?? '')).toContain('TEXT');
		expect(String(columns.refresh?.type ?? '')).toContain('TEXT');
	});
});
