import { Sequelize } from 'sequelize';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { SqlAuthStore } from '../../src/auth-api/sql-auth-store';
import { SequelizeTokenStore } from '../../src/token/sequelize.js';
import { describeSequelizeSuite } from '../helpers/sequelize-targets.js';

await describeSequelizeSuite(
	'SqlAuthStore mixed databases',
	({ target, getSequelize }) => {
		if (target.dialect !== 'postgres') {
			describe.skip(target.label, () => {});
			return;
		}

		let tokenSequelize: Sequelize;
		let store: SqlAuthStore;
		let mainSequelize: Sequelize;

		beforeEach(async () => {
			mainSequelize = getSequelize();
			tokenSequelize = new Sequelize({
				dialect: 'sqlite',
				storage: ':memory:',
				logging: false
			});
			const tokenStore = new SequelizeTokenStore({
				sequelize: tokenSequelize
			});
			await tokenSequelize.sync({ force: true });

			store = new SqlAuthStore({
				sequelize: mainSequelize,
				tokenStore,
				passkeys: false
			});
			await store.initialise(true);
		});

		afterEach(async () => {
			await store?.close();
			await tokenSequelize?.close();
		});

		it('stores tokens in sqlite while users/oauth live in postgres', async () => {
			const created = await store.userStore.createUser({
				login: `mixed-user-${Date.now()}`,
				email: `mixed-${Date.now()}@example.com`,
				password: 'secret'
			});
			const userId = store.getUserId(created);

			await store.storeToken({
				refreshToken: 'mix-refresh',
				accessToken: 'mix-access',
				userId,
				clientId: 'app-mix',
				scope: ['read'],
				expires: new Date(Date.now() + 30_000)
			});

			const fetched = await store.getToken({
				refreshToken: 'mix-refresh'
			});
			expect(String(fetched?.userId)).toEqual(String(userId));
			expect(fetched?.clientId).toBe('app-mix');
			expect(mainSequelize.getDialect()).toBe('postgres');
			expect(tokenSequelize.getDialect()).toBe('sqlite');
		});
	},
	{ filterTargets: (target) => target.dialect === 'postgres' }
);
