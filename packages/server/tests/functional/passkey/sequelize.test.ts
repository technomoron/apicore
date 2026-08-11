import { expect, it } from 'vitest';

import { SequelizePasskeyStore } from '../../../src/passkey/sequelize.js';
import { describeSequelizeSuite, listSequelizeTables } from '../../helpers/sequelize-targets.js';

import { runPasskeyStoreSuite } from './passkey-store-suite.js';

await describeSequelizeSuite('SequelizePasskeyStore', ({ target, getSequelize }) => {
	runPasskeyStoreSuite(target.label, async () => {
		const sequelize = getSequelize();
		const store = new SequelizePasskeyStore({
			sequelize,
			resolveUser: async (params) => {
				const id = (params.userId ?? 1) as number;
				return {
					id,
					login: params.login ?? 'alice',
					displayName: params.login ?? 'alice'
				};
			}
		});
		await sequelize.sync({ force: true });
		return {
			store,
			cleanup: async () => {}
		};
	});

	it('supports table prefixes', async () => {
		const sequelize = getSequelize();
		new SequelizePasskeyStore({
			sequelize,
			tablePrefix: 'myapp_',
			resolveUser: async (params) => {
				const id = (params.userId ?? 1) as number;
				return {
					id,
					login: params.login ?? 'alice',
					displayName: params.login ?? 'alice'
				};
			}
		});
		await sequelize.sync({ force: true });

		const tables = await listSequelizeTables(sequelize);
		expect(tables).toContain('myapp_passkey_credentials');
		expect(tables).toContain('myapp_passkey_challenges');
	});
});
