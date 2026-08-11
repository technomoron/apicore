import { describe, expect, it } from 'vitest';

import { ApiModule } from '../../src/api-module';
import { TestServer } from '../helpers/test-server';

class EmptyModule extends ApiModule<TestServer> {
	constructor() {
		super({ namespace: '/empty' });
	}
	defineRoutes() {
		return [];
	}
}

describe('ApiServer finalize()', () => {
	it('prevents registering new endpoints after finalize', () => {
		const server = new TestServer();
		server.finalize();

		expect(() => server.useExpress('/api/custom/ping', (_req, res) => res.status(200).json({ ok: true }))).toThrow(
			'Cannot call ApiServer.useExpress() after finalize()/start()'
		);
		expect(() => server.api(new EmptyModule())).toThrow('Cannot call ApiServer.api() after finalize()/start()');
	});
});
