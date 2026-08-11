import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';

import ApiServer from '../../../src/apicore-server';
import AuthModule from '../../../src/auth-api/auth-module';
import { CompositeAuthAdapter } from '../../../src/auth-api/compat-auth-storage';
import { BaseAuthAdapter } from '../../../src/auth-api/storage';
import { MemoryPasskeyStore } from '../../../src/passkey/memory';
import { PasskeyService } from '../../../src/passkey/service';
import { MemoryTokenStore } from '../../../src/token/memory';
import { MemoryUserStore } from '../../../src/user/memory';

import type {
	PasskeyChallenge,
	PasskeyChallengeParams,
	PasskeyVerificationParams,
	PasskeyVerificationResult
} from '../../../src/passkey/types';

type TestUser = { user_id: string; login: string; password: string };

class InheritedLookupAdapter extends BaseAuthAdapter<TestUser, TestUser> {
	public readonly passkeyService = {};

	public override async createPasskeyChallenge(params: PasskeyChallengeParams): Promise<PasskeyChallenge> {
		void params;
		throw new Error('must not be called');
	}

	public override async verifyPasskeyResponse(
		params: PasskeyVerificationParams
	): Promise<PasskeyVerificationResult> {
		void params;
		throw new Error('must not be called');
	}
}

function mountAuth(storage: BaseAuthAdapter<TestUser, TestUser> | CompositeAuthAdapter<unknown, unknown>) {
	const server = new ApiServer({
		apiBasePath: '/api',
		accessSecret: 'access-secret',
		refreshSecret: 'refresh-secret'
	}).authStorage(storage);
	const authModule = new AuthModule({});
	server.authModule(authModule);
	server.api(authModule);
	return request(server.app);
}

function compositeWithoutLookup(): CompositeAuthAdapter<unknown, unknown> {
	const userStore = new MemoryUserStore();
	const passkeyStore = new MemoryPasskeyStore({ resolveUser: async () => null });
	const storage = new CompositeAuthAdapter({
		userStore,
		tokenStore: new MemoryTokenStore(),
		passkeys: new PasskeyService(
			{
				rpId: 'localhost',
				rpName: 'API Server',
				origins: ['http://localhost:5173'],
				timeoutMs: 300_000,
				userVerification: 'preferred'
			},
			passkeyStore
		)
	});
	(storage as unknown as { getPasskeyChallenge?: unknown }).getPasskeyChallenge = undefined;
	return storage;
}

async function expectPasskeyRoutesNotMounted(agent: request.SuperTest<request.Test>): Promise<void> {
	const challenge = await agent.post('/api/auth/v1/passkeys/challenge').send({ action: 'authenticate' });
	const verify = await agent.post('/api/auth/v1/passkeys/verify').send({
		expectedChallenge: 'missing',
		response: {}
	});

	expect(challenge.status).toBe(404);
	expect(verify.status).toBe(404);
}

describe('passkey capability detection', () => {
	it('does not treat the inherited BaseAuthAdapter challenge stub as support', async () => {
		const agent = mountAuth(new InheritedLookupAdapter());
		await expectPasskeyRoutesNotMounted(agent);
	});

	it('does not mount a challenge route that leads to an unusable verify route', async () => {
		const storage = compositeWithoutLookup();
		const verifySpy = vi.spyOn(storage, 'verifyPasskeyResponse');
		const agent = mountAuth(storage);

		await expectPasskeyRoutesNotMounted(agent);
		expect(verifySpy).not.toHaveBeenCalled();
	});
});
