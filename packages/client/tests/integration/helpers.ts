import { ApiServer, AuthModule, MemAuthStore } from '@technomoron/apicore-server';

import ApiClient from '../../src/index.js';

import type { AddressInfo } from 'node:net';

export interface IntegrationHarness {
	client: ApiClient;
	store: MemAuthStore;
	port: number;
	stop: () => Promise<void>;
}

export async function createIntegrationHarness(): Promise<IntegrationHarness> {
	const store = new MemAuthStore();
	await store.initialise();

	await store.userStore.createUser({
		login: 'alice',
		email: 'alice@test.com',
		password: 'pass123'
	});

	const server = new ApiServer({
		accessSecret: 'test-access-secret',
		refreshSecret: 'test-refresh-secret'
	});
	server.authStorage(store);

	const authModule = new AuthModule();
	server.authModule(authModule);
	server.api(authModule);

	const httpServer = server.app.listen(0);
	await new Promise<void>((res) => httpServer.once('listening', res));
	const port = (httpServer.address() as AddressInfo).port;

	const client = new ApiClient(`http://localhost:${port}`);

	const stop = (): Promise<void> =>
		new Promise((res, rej) => {
			httpServer.close((err) => (err ? rej(err) : res()));
		});

	return { client, store, port, stop };
}
