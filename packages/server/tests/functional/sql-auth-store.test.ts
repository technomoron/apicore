import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { DataTypes, Sequelize } from 'sequelize';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { SqlAuthStore } from '../../src/auth-api/sql-auth-store';
import { describeSequelizeSuite } from '../helpers/sequelize-targets.js';

import type { AuthIdentifier } from '../../src/auth-api/types.js';

await describeSequelizeSuite('SqlAuthStore', ({ getSequelize }) => {
	let sequelize: Sequelize;
	let store: SqlAuthStore;
	let userId: AuthIdentifier;
	let testUserCounter = 0;
	let baseUser: { login: string; email: string; password: string };

	beforeEach(async () => {
		testUserCounter += 1;
		baseUser = {
			login: `jane-${testUserCounter}`,
			email: `jane-${testUserCounter}@example.com`,
			password: 'super-secret'
		};
		sequelize = getSequelize();
		store = new SqlAuthStore({ sequelize });
		await store.initialise(true);
		await sequelize.sync({ force: true });
		const user = await store.userStore.createUser(baseUser);
		userId = store.getUserId(user);
	});

	afterEach(async () => {
		await store?.close();
	});

	it('creates users and finds them by multiple identifiers', async () => {
		const byLogin = await store.getUser(baseUser.login);
		expect(byLogin?.login).toBe(baseUser.login);

		const byEmail = await store.getUser(baseUser.email);
		expect(byEmail?.email).toBe(baseUser.email);

		const byId = await store.getUser(userId);
		expect(byId?.login).toBe(baseUser.login);

		if (byLogin) {
			const hash = store.getUserPasswordHash(byLogin);
			expect(await store.verifyPassword(baseUser.password, hash)).toBe(true);
			expect(await store.verifyPassword('bad-password', hash)).toBe(false);
		}
	});

	it('stores, retrieves, updates, and deletes tokens', async () => {
		await store.storeToken({
			accessToken: 'access-token',
			refreshToken: 'refresh-token',
			userId,
			clientId: 'app-1',
			scope: ['profile', 'email'],
			expires: new Date(Date.now() + 60_000),
			domain: 'example.com',
			fingerprint: 'fp-1',
			label: 'primary',
			browser: 'Firefox',
			device: 'Mac',
			ip: '127.0.0.1',
			os: 'macOS',
			loginType: 'password'
		});

		const token = await store.getToken({
			refreshToken: 'refresh-token',
			clientId: 'app-1'
		});
		expect(token?.refreshToken).toBe('refresh-token');
		expect(token?.clientId).toBe('app-1');
		expect(token?.scope).toEqual(['profile', 'email']);

		const updated = await store.updateToken?.({
			refreshToken: 'refresh-token',
			clientId: 'app-1',
			accessToken: 'new-access',
			scope: ['profile'],
			label: 'updated',
			domain: 'updated.example.com',
			fingerprint: 'fp-2'
		});
		expect(updated).toBe(true);

		const fetched = await store.getToken({
			refreshToken: 'refresh-token',
			clientId: 'app-1'
		});
		expect(fetched?.accessToken).toBe('new-access');
		expect(fetched?.label).toBe('updated');
		expect(fetched?.domain).toBe('updated.example.com');
		expect(fetched?.fingerprint).toBe('fp-2');

		const removed = await store.deleteToken({
			refreshToken: 'refresh-token',
			clientId: 'app-1'
		});
		expect(removed).toBe(1);
		const missing = await store.getToken({
			refreshToken: 'refresh-token',
			clientId: 'app-1'
		});
		expect(missing).toBeNull();
	});

	it('filters user fields for public exposure', async () => {
		const user = await store.getUser(baseUser.login);
		expect(user).toBeTruthy();
		if (!user) {
			return;
		}
		const safe = store.filterUser(user);
		expect(safe.login).toBe(baseUser.login);
		expect(safe).not.toHaveProperty('password');
	});

	it('manages OAuth clients and authorization codes', async () => {
		const client = await store.oauthStore.createClient({
			clientId: 'oauth-app',
			clientSecret: 'top-secret',
			redirectUris: ['https://app.example.com/callback'],
			scope: ['profile']
		});

		const loaded = await store.getClient(client.clientId);
		expect(loaded?.clientId).toBe(client.clientId);
		expect(await store.verifyClientSecret(client, 'top-secret')).toBe(true);
		expect(await store.verifyClientSecret(client, 'wrong')).toBe(false);

		const codeRecord = await store.createAuthCode({
			clientId: client.clientId,
			userId,
			redirectUri: 'https://app.example.com/callback',
			scope: ['profile']
		});

		const consumed = await store.consumeAuthCode(codeRecord.code, client.clientId);
		expect(consumed).not.toBeNull();
		expect(consumed?.clientId).toBe(client.clientId);
		expect(consumed?.scope).toEqual(['profile']);

		const missing = await store.consumeAuthCode(codeRecord.code, client.clientId);
		expect(missing).toBeNull();
	});

	it('creates passkey challenges for registered users', async () => {
		const challenge = await store.createPasskeyChallenge?.({
			action: 'register',
			login: baseUser.login,
			userId
		});

		expect(challenge).toBeTruthy();
		expect(challenge?.challenge).toBeTypeOf('string');
	});
});

describe('SqlAuthStore migrations', () => {
	it('adds missing token metadata columns when altering legacy tables', async () => {
		const tempDir = await mkdtemp(join(tmpdir(), 'sql-auth-store-'));
		const storage = join(tempDir, 'legacy.sqlite');

		try {
			const bootstrap = new Sequelize({
				dialect: 'sqlite',
				storage,
				logging: false
			});
			const queryInterface = bootstrap.getQueryInterface();
			await queryInterface.createTable('jwttokens', {
				token_id: {
					type: DataTypes.INTEGER,
					autoIncrement: true,
					allowNull: false,
					primaryKey: true
				},
				user_id: {
					type: DataTypes.STRING(191),
					allowNull: false
				},
				expires: {
					type: DataTypes.DATE,
					allowNull: false
				},
				access: {
					type: DataTypes.STRING(512),
					allowNull: false
				},
				refresh: {
					type: DataTypes.STRING(512),
					allowNull: false
				},
				domain: {
					type: DataTypes.STRING(64),
					allowNull: false,
					defaultValue: ''
				},
				fingerprint: {
					type: DataTypes.STRING(64),
					allowNull: false,
					defaultValue: ''
				},
				label: {
					type: DataTypes.STRING(128),
					allowNull: false,
					defaultValue: ''
				},
				client_id: {
					type: DataTypes.STRING(128)
				},
				scope: {
					type: DataTypes.TEXT,
					allowNull: false,
					defaultValue: '[]'
				}
			});
			await bootstrap.close();

			const store = new SqlAuthStore({
				sequelize: new Sequelize({
					dialect: 'sqlite',
					storage,
					logging: false
				}),
				syncOptions: { alter: true }
			});
			await store.initialise(true);
			await store.close();

			const inspector = new Sequelize({
				dialect: 'sqlite',
				storage,
				logging: false
			});
			const columns = await inspector.getQueryInterface().describeTable('jwttokens');
			await inspector.close();

			expect(columns).toHaveProperty('issued_at');
			expect(columns).toHaveProperty('last_seen_at');
			expect(columns).toHaveProperty('browser');
			expect(columns).toHaveProperty('device');
			expect(columns).toHaveProperty('ip');
			expect(columns).toHaveProperty('os');
			expect(columns).toHaveProperty('login_type');
			expect(columns).toHaveProperty('refresh_ttl_seconds');
			expect(columns).toHaveProperty('session_cookie');
			expect(columns).toHaveProperty('session_id');
			expect(columns).toHaveProperty('real_user_id');
		} finally {
			await rm(tempDir, { recursive: true, force: true });
		}
	});
});
