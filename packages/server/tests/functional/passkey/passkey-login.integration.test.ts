import { isoBase64URL } from '@simplewebauthn/server/helpers';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import ApiServer from '../../../src/apicore-server';
import AuthModule from '../../../src/auth-api/auth-module';
import { CompositeAuthAdapter } from '../../../src/auth-api/compat-auth-storage';
import { MemoryPasskeyStore } from '../../../src/passkey/memory';
import { PasskeyService } from '../../../src/passkey/service';
import { MemoryTokenStore } from '../../../src/token/memory';
import { MemoryUserStore, type MemoryUserAttributes } from '../../../src/user/memory';

import { FakePasskeyClient } from './fake-passkey-client.js';

import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';

const verifyRegistrationResponse = vi.hoisted(() => vi.fn());
const verifyAuthenticationResponse = vi.hoisted(() => vi.fn());

vi.mock('@simplewebauthn/server', async () => {
	const actual = await vi.importActual<typeof import('@simplewebauthn/server')>('@simplewebauthn/server');
	return {
		...actual,
		verifyRegistrationResponse,
		verifyAuthenticationResponse
	};
});

const serverConfig = {
	apiBasePath: '/api',
	accessSecret: 'access-secret',
	refreshSecret: 'refresh-secret',
	accessCookie: 'access',
	refreshCookie: 'refresh',
	cookieDomain: ''
} as const;

const passkeyConfig = {
	rpId: 'localhost',
	rpName: 'API Server',
	origins: ['http://localhost:5173'],
	timeoutMs: 5 * 60 * 1000,
	userVerification: 'preferred' as const
};

const userInput = {
	login: 'sally',
	email: 'sally@example.com',
	password: 'super-secret'
};

const passkeyCredentialId = isoBase64URL.fromBuffer(Buffer.from('passkey-cred-1'));
let registeredCredentialId: string | null = null;
let registrationOverride: {
	credentialId?: Buffer;
	publicKey?: Buffer;
	counter?: number;
	transports?: string[];
} | null = null;

interface PasskeyHarness {
	server: ApiServer;
	agent: request.SuperTest<request.Test>;
	user: MemoryUserAttributes;
	passkeyStore: MemoryPasskeyStore;
	tokenStore: MemoryTokenStore;
	logger: Pick<typeof console, 'error' | 'warn'>;
}

let authChallengeFromServer: string | null = null;

function mockSuccessfulWebAuthnVerification(): void {
	verifyRegistrationResponse.mockImplementation(async ({ response }) => {
		const id = Buffer.from(isoBase64URL.toBuffer(String((response as RegistrationResponseJSON).id)));
		const credentialId = registrationOverride?.credentialId ?? id;
		const publicKey = registrationOverride?.publicKey ?? Buffer.from('public-key');
		const counter = registrationOverride?.counter ?? 0;
		registeredCredentialId = isoBase64URL.fromBuffer(credentialId);
		return {
			verified: true,
			registrationInfo: {
				credential: {
					id: registeredCredentialId,
					publicKey: new Uint8Array(publicKey),
					counter,
					transports: registrationOverride?.transports ?? ['internal']
				},
				credentialBackedUp: true,
				credentialDeviceType: 'multiDevice'
			}
		};
	});

	verifyAuthenticationResponse.mockImplementation(async ({ response, expectedChallenge, credential }) => {
		const id = String((response as AuthenticationResponseJSON).id);
		const matchesChallenge = expectedChallenge === authChallengeFromServer;
		const expectedId = registeredCredentialId ?? passkeyCredentialId;
		const matchesCredential = id === expectedId;
		return {
			verified: matchesChallenge && matchesCredential,
			authenticationInfo: {
				newCounter: (credential?.counter ?? 0) + 1
			}
		};
	});
}

beforeEach(() => {
	authChallengeFromServer = null;
	registeredCredentialId = null;
	registrationOverride = null;
	verifyRegistrationResponse.mockReset();
	verifyAuthenticationResponse.mockReset();
	mockSuccessfulWebAuthnVerification();
});

afterEach(() => {
	vi.restoreAllMocks();
});

async function createHarness(logger: Pick<typeof console, 'error' | 'warn'> = console): Promise<PasskeyHarness> {
	const userStore = new MemoryUserStore();
	const user = await userStore.createUser(userInput);
	const tokenStore = new MemoryTokenStore();
	const passkeyStore = new MemoryPasskeyStore({
		resolveUser: async (params) => {
			if (params.userId) {
				const found = await userStore.findById(params.userId);
				return found
					? {
							id: found.user_id,
							login: found.login,
							displayName: found.login
						}
					: null;
			}
			if (params.login) {
				const found = await userStore.findUser(params.login);
				return found
					? {
							id: found.user_id,
							login: found.login,
							displayName: found.login
						}
					: null;
			}
			return null;
		}
	});
	const passkeyService = new PasskeyService(passkeyConfig, passkeyStore, logger);

	const storage = new CompositeAuthAdapter({
		userStore,
		tokenStore,
		passkeys: passkeyService
	});
	const server = new ApiServer({
		...serverConfig
	}).authStorage(storage);

	const authModule = new AuthModule({
		defaultDomain: serverConfig.cookieDomain
	});
	server.authModule(authModule);
	server.api(authModule);

	const agent = request(server.app) as unknown as request.SuperTest<request.Test>;

	return { server, agent, user, passkeyStore, tokenStore, logger };
}

async function createHarnessWithConfig(
	config: typeof passkeyConfig,
	logger: Pick<typeof console, 'error' | 'warn'> = console
): Promise<PasskeyHarness> {
	const userStore = new MemoryUserStore();
	const user = await userStore.createUser(userInput);
	const tokenStore = new MemoryTokenStore();
	const passkeyStore = new MemoryPasskeyStore({
		resolveUser: async (params) => {
			if (params.userId) {
				const found = await userStore.findById(params.userId);
				return found
					? {
							id: found.user_id,
							login: found.login,
							displayName: found.login
						}
					: null;
			}
			if (params.login) {
				const found = await userStore.findUser(params.login);
				return found
					? {
							id: found.user_id,
							login: found.login,
							displayName: found.login
						}
					: null;
			}
			return null;
		}
	});
	const passkeyService = new PasskeyService(config, passkeyStore, logger);

	const storage = new CompositeAuthAdapter({
		userStore,
		tokenStore,
		passkeys: passkeyService
	});
	const server = new ApiServer({
		...serverConfig
	}).authStorage(storage);

	const authModule = new AuthModule({
		defaultDomain: serverConfig.cookieDomain
	});
	server.authModule(authModule);
	server.api(authModule);

	const agent = request(server.app) as unknown as request.SuperTest<request.Test>;

	return { server, agent, user, passkeyStore, tokenStore, logger };
}

function buildRegistrationResponse(): RegistrationResponseJSON {
	return {
		id: passkeyCredentialId,
		rawId: passkeyCredentialId,
		response: {
			attestationObject: 'attestation-data',
			clientDataJSON: 'client-data'
		},
		type: 'public-key',
		clientExtensionResults: {}
	};
}

function buildAuthenticationResponse(
	options: { publicKey?: Record<string, unknown> },
	userId: number
): AuthenticationResponseJSON {
	const allowCredentials = options.publicKey?.allowCredentials as Array<{ id: string }> | undefined;
	if (!allowCredentials || allowCredentials.length === 0) {
		throw new Error('Auth challenge must include allowCredentials');
	}
	const credentialId = allowCredentials[0].id;
	return {
		id: credentialId,
		rawId: credentialId,
		response: {
			authenticatorData: 'auth-data',
			clientDataJSON: 'client-data',
			signature: 'signature',
			userHandle: isoBase64URL.fromBuffer(Buffer.from(String(userId)))
		},
		type: 'public-key',
		clientExtensionResults: {}
	};
}

interface PasskeyRegistrationMetadata {
	label?: string;
	domain?: string;
	browser?: string;
	device?: string;
	os?: string;
	ip?: string;
	userAgent?: string;
}

async function loginViaApi(harness: PasskeyHarness): Promise<{ accessToken: string; refreshToken: string }> {
	const response = await harness.agent
		.post('/api/auth/v1/login')
		.send({ login: harness.user.login, password: userInput.password });

	expect(response.status).toBe(200);
	expect(response.body.code).toBe(200);

	return response.body.data as { accessToken: string; refreshToken: string };
}

async function registerPasskeyViaApi(
	harness: PasskeyHarness,
	metadata: PasskeyRegistrationMetadata = {}
): Promise<{
	accessToken: string;
	refreshToken: string;
}> {
	const session = await loginViaApi(harness);
	const authorization = `Bearer ${session.accessToken}`;
	const challengeRes = await harness.agent
		.post('/api/auth/v1/passkeys/challenge')
		.set('Authorization', authorization)
		.send({
			action: 'register',
			login: harness.user.login,
			userId: harness.user.user_id
		});

	expect(challengeRes.status).toBe(200);
	expect(challengeRes.body.code).toBe(200);

	const { challenge } = challengeRes.body.data as { challenge: string };

	const verifyRes = await harness.agent
		.post('/api/auth/v1/passkeys/verify')
		.set('Authorization', authorization)
		.send({
			expectedChallenge: challenge,
			response: buildRegistrationResponse(),
			login: harness.user.login,
			userId: harness.user.user_id,
			...metadata
		});

	expect(verifyRes.status).toBe(200);
	expect(verifyRes.body.code).toBe(200);

	return verifyRes.body.data as { accessToken: string; refreshToken: string };
}

describe('Passkey login via API endpoints', () => {
	it('stores credential metadata from the registration verify request', async () => {
		const harness = await createHarness();
		const metadata: PasskeyRegistrationMetadata = {
			label: 'Work Mac',
			domain: 'example.com',
			browser: 'Chrome 123.0',
			os: 'macOS 14.0',
			device: 'Mac',
			ip: '203.0.113.20',
			userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0_0)'
		};

		await registerPasskeyViaApi(harness, metadata);
		const credentials = await harness.passkeyStore.listUserCredentials(harness.user.user_id);

		expect(credentials.length).toBe(1);
		expect(credentials[0].label).toBe('Work Mac');
		expect(credentials[0].createdDomain).toBe('example.com');
		expect(credentials[0].createdBrowser).toBe('Chrome 123.0');
		expect(credentials[0].createdOs).toBe('macOS 14.0');
		expect(credentials[0].createdDevice).toBe('Mac');
		expect(credentials[0].createdIp).toBe('203.0.113.20');
		expect(credentials[0].createdUserAgent).toBe('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0_0)');
	});

	it('registers, lists credentials, and exposes auth options with rpId and allowCredentials', async () => {
		const harness = await createHarness();
		const tokens = await registerPasskeyViaApi(harness);

		const listRes = await harness.agent
			.get('/api/auth/v1/passkeys')
			.set('Authorization', `Bearer ${tokens.accessToken}`);

		expect(listRes.status).toBe(200);
		const credentials = (listRes.body.data?.credentials ?? []) as Array<{
			id: string;
		}>;
		expect(credentials.length).toBe(1);
		expect(credentials[0].id).toBe(passkeyCredentialId);

		const authChallenge = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.send({ action: 'authenticate', login: harness.user.login });

		expect(authChallenge.status).toBe(200);
		expect(authChallenge.body.code).toBe(200);
		const data = authChallenge.body.data as Record<string, unknown>;
		authChallengeFromServer = data.challenge;

		expect(typeof data.challenge).toBe('string');
		expect(data.userId).toBe(harness.user.user_id);

		const publicKey = data.publicKey;
		expect(publicKey).toBeTypeOf('object');
		expect(publicKey.rpId).toBe(passkeyConfig.rpId);
		expect(publicKey.userVerification).toBe(passkeyConfig.userVerification);

		const allowCredentials = publicKey.allowCredentials as Array<{ id: string; type: string }> | undefined;
		expect(Array.isArray(allowCredentials)).toBe(true);
		expect(allowCredentials?.length).toBe(1);
		expect(allowCredentials?.[0].type).toBe('public-key');
		expect(allowCredentials?.[0].id).toBe(passkeyCredentialId);
	});

	it('supports a full register -> authenticate -> verify round-trip using server-provided options', async () => {
		const harness = await createHarness();
		await registerPasskeyViaApi(harness);

		const authChallenge = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.send({ action: 'authenticate', login: harness.user.login });

		expect(authChallenge.status).toBe(200);
		const data = authChallenge.body.data as Record<string, unknown>;
		authChallengeFromServer = data.challenge;

		const assertion = buildAuthenticationResponse(
			{
				publicKey: data.publicKey as Record<string, unknown> | undefined
			},
			harness.user.user_id
		);

		const verifyRes = await harness.agent.post('/api/auth/v1/passkeys/verify').send({
			expectedChallenge: data.challenge,
			response: assertion,
			login: harness.user.login,
			userId: harness.user.user_id
		});

		expect(verifyRes.status).toBe(200);
		expect(verifyRes.body.data?.accessToken).toBeTypeOf('string');
		expect(verifyRes.body.data?.refreshToken).toBeTypeOf('string');
		expect(verifyRes.body.data?.user?.login).toBe(harness.user.login);
	});

	it('requires user verification by default when verifying registration/authentication', async () => {
		const harness = await createHarness();
		await registerPasskeyViaApi(harness);
		expect(verifyRegistrationResponse).toHaveBeenCalled();
		expect(verifyRegistrationResponse.mock.calls.at(-1)?.[0]?.requireUserVerification).toBe(true);

		const authChallenge = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.send({ action: 'authenticate', login: harness.user.login });
		const data = authChallenge.body.data as Record<string, unknown>;
		authChallengeFromServer = data.challenge as string;

		const verifyRes = await harness.agent.post('/api/auth/v1/passkeys/verify').send({
			expectedChallenge: data.challenge,
			response: buildAuthenticationResponse(
				{
					publicKey: data.publicKey as Record<string, unknown> | undefined
				},
				harness.user.user_id
			),
			login: harness.user.login,
			userId: harness.user.user_id
		});
		expect(verifyRes.status).toBe(200);
		expect(verifyAuthenticationResponse).toHaveBeenCalled();
		expect(verifyAuthenticationResponse.mock.calls.at(-1)?.[0]?.requireUserVerification).toBe(true);
	});

	it('disables required user verification when configured as discouraged', async () => {
		const harness = await createHarnessWithConfig({
			...passkeyConfig,
			userVerification: 'discouraged'
		});
		await registerPasskeyViaApi(harness);
		expect(verifyRegistrationResponse).toHaveBeenCalled();
		expect(verifyRegistrationResponse.mock.calls.at(-1)?.[0]?.requireUserVerification).toBe(false);

		const authChallenge = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.send({ action: 'authenticate', login: harness.user.login });
		const data = authChallenge.body.data as Record<string, unknown>;
		authChallengeFromServer = data.challenge as string;

		const verifyRes = await harness.agent.post('/api/auth/v1/passkeys/verify').send({
			expectedChallenge: data.challenge,
			response: buildAuthenticationResponse(
				{
					publicKey: data.publicKey as Record<string, unknown> | undefined
				},
				harness.user.user_id
			),
			login: harness.user.login,
			userId: harness.user.user_id
		});
		expect(verifyRes.status).toBe(200);
		expect(verifyAuthenticationResponse).toHaveBeenCalled();
		expect(verifyAuthenticationResponse.mock.calls.at(-1)?.[0]?.requireUserVerification).toBe(false);
	});

	it('stores the credential returned by SimpleWebAuthn instead of client-supplied registration fields', async () => {
		const logger = { error: vi.fn(), warn: vi.fn() } as unknown as Pick<typeof console, 'error' | 'warn'>;
		const harness = await createHarness(logger);
		const verifiedCredentialId = Buffer.from('verified-credential-id');
		const verifiedPublicKey = Buffer.from('verified-public-key');
		registrationOverride = {
			credentialId: verifiedCredentialId,
			publicKey: verifiedPublicKey,
			counter: 42,
			transports: ['usb']
		};

		await registerPasskeyViaApi(harness);
		const credentials = await harness.passkeyStore.listUserCredentials(harness.user.user_id);
		expect(credentials.length).toBe(1);
		expect(credentials[0].credentialId).toEqual(verifiedCredentialId);
		expect(credentials[0].publicKey).toEqual(verifiedPublicKey);
		expect(credentials[0].counter).toBe(42);
		expect(credentials[0].transports).toEqual(['usb']);

		const authChallenge = await harness.agent.post('/api/auth/v1/passkeys/challenge').send({
			action: 'authenticate',
			login: harness.user.login,
			userId: harness.user.user_id
		});
		const data = authChallenge.body.data as Record<string, unknown>;
		authChallengeFromServer = data.challenge;
		const assertion = buildAuthenticationResponse(
			{
				publicKey: data.publicKey as Record<string, unknown> | undefined
			},
			harness.user.user_id
		);
		const verifyRes = await harness.agent.post('/api/auth/v1/passkeys/verify').send({
			expectedChallenge: data.challenge,
			response: assertion
		});
		expect(verifyRes.status).toBe(200);
		expect(logger.error).not.toHaveBeenCalled();
	});

	it('rejects registration when both credential id and public key are missing', async () => {
		const logger = { error: vi.fn(), warn: vi.fn() } as unknown as Pick<typeof console, 'error' | 'warn'>;
		const harness = await createHarness(logger);
		registrationOverride = {
			credentialId: Buffer.alloc(0),
			publicKey: Buffer.alloc(0)
		};

		const session = await loginViaApi(harness);
		const challengeRes = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.set('Authorization', `Bearer ${session.accessToken}`)
			.send({
				action: 'register',
				login: harness.user.login,
				userId: harness.user.user_id
			});
		const { challenge } = challengeRes.body.data as { challenge: string };

		const verifyRes = await harness.agent
			.post('/api/auth/v1/passkeys/verify')
			.set('Authorization', `Bearer ${session.accessToken}`)
			.send({
				expectedChallenge: challenge,
				response: buildRegistrationResponse(),
				login: harness.user.login,
				userId: harness.user.user_id
			});
		expect(verifyRes.status).toBe(401);
		const credentials = await harness.passkeyStore.listUserCredentials(harness.user.user_id);
		expect(credentials.length).toBe(0);
	});

	it('rejects unauthenticated registration verification before persisting credentials', async () => {
		const harness = await createHarness();
		const session = await loginViaApi(harness);
		const challengeRes = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.set('Authorization', `Bearer ${session.accessToken}`)
			.send({
				action: 'register',
				login: harness.user.login,
				userId: harness.user.user_id
			});

		expect(challengeRes.status).toBe(200);
		const { challenge } = challengeRes.body.data as { challenge: string };

		const verifyRes = await harness.agent.post('/api/auth/v1/passkeys/verify').send({
			expectedChallenge: challenge,
			response: buildRegistrationResponse(),
			login: harness.user.login,
			userId: harness.user.user_id
		});

		expect(verifyRes.status).toBe(401);
		expect(verifyRes.body.message).toBe('Passkey registration requires authentication');
		const credentials = await harness.passkeyStore.listUserCredentials(harness.user.user_id);
		expect(credentials.length).toBe(0);
	});

	it('logs verification errors when authentication fails', async () => {
		const logger = { error: vi.fn(), warn: vi.fn() };
		const harness = await createHarness(logger);
		await registerPasskeyViaApi(harness);

		const authChallenge = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.send({ action: 'authenticate', login: harness.user.login });

		expect(authChallenge.status).toBe(200);
		const data = authChallenge.body.data as Record<string, unknown>;
		authChallengeFromServer = data.challenge;

		verifyAuthenticationResponse.mockResolvedValueOnce({
			verified: false,
			error: new Error('bad assertion')
		});

		const verifyRes = await harness.agent.post('/api/auth/v1/passkeys/verify').send({
			expectedChallenge: data.challenge,
			response: {
				id: passkeyCredentialId,
				rawId: passkeyCredentialId,
				type: 'public-key',
				response: {
					authenticatorData: 'auth-data',
					clientDataJSON: 'client-data',
					signature: 'signature',
					userHandle: isoBase64URL.fromBuffer(Buffer.from(String(harness.user.user_id)))
				}
			},
			login: harness.user.login,
			userId: harness.user.user_id
		});

		expect(verifyRes.status).toBe(401);
		expect(logger.error).toHaveBeenCalled();
	});

	it('can register and authenticate through a fake browser passkey client', async () => {
		const harness = await createHarness();
		const client = new FakePasskeyClient({
			rpId: passkeyConfig.rpId,
			origin: passkeyConfig.origins[0],
			userId: harness.user.user_id,
			credentialId: isoBase64URL.fromBuffer(Buffer.from('passkey-plugin-cred'))
		});

		const session = await loginViaApi(harness);
		const regChallenge = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.set('Authorization', `Bearer ${session.accessToken}`)
			.send({ action: 'register', login: harness.user.login });

		expect(regChallenge.status).toBe(200);
		const regData = regChallenge.body.data as Record<string, unknown>;
		const registrationResponse = client.createRegistrationResponse(regData);

		const regVerify = await harness.agent
			.post('/api/auth/v1/passkeys/verify')
			.set('Authorization', `Bearer ${session.accessToken}`)
			.send({
				expectedChallenge: regData.challenge,
				response: registrationResponse,
				login: harness.user.login,
				userId: harness.user.user_id
			});
		expect(regVerify.status).toBe(200);

		const authChallenge = await harness.agent
			.post('/api/auth/v1/passkeys/challenge')
			.send({ action: 'authenticate', login: harness.user.login });

		expect(authChallenge.status).toBe(200);
		const authData = authChallenge.body.data as Record<string, unknown>;
		authChallengeFromServer = authData.challenge;
		const assertion = client.createAuthenticationResponse(authData);

		const authVerify = await harness.agent.post('/api/auth/v1/passkeys/verify').send({
			expectedChallenge: authData.challenge,
			response: assertion,
			login: harness.user.login,
			userId: harness.user.user_id
		});

		expect(authVerify.status).toBe(200);
		expect(authVerify.body.data?.user?.login).toBe(harness.user.login);
	});
});

async function registerPasskeyDirect(harness: PasskeyHarness): Promise<void> {
	const challenge = await harness.server.createPasskeyChallenge({
		action: 'register',
		login: harness.user.login,
		userId: harness.user.user_id
	});
	expect(challenge.challenge).toBeTypeOf('string');
	const registrationResponse = buildRegistrationResponse();
	const result = await harness.server.verifyPasskeyResponse({
		expectedChallenge: String(challenge.challenge),
		response: registrationResponse,
		login: harness.user.login,
		userId: harness.user.user_id
	});
	expect(result.verified).toBe(true);
}

describe('Passkey service direct calls', () => {
	it('registers and authenticates using server helpers and server-provided options', async () => {
		const harness = await createHarness();
		await registerPasskeyDirect(harness);

		const authChallenge = await harness.server.createPasskeyChallenge({
			action: 'authenticate',
			login: harness.user.login,
			userId: harness.user.user_id
		});

		authChallengeFromServer = String(authChallenge.challenge);
		expect(authChallenge.challenge).toBeTypeOf('string');

		const publicKey = authChallenge.publicKey as Record<string, unknown> | undefined;
		expect(publicKey).toBeTypeOf('object');

		const assertion = buildAuthenticationResponse({ publicKey }, harness.user.user_id);

		const verifyRes = await harness.server.verifyPasskeyResponse({
			expectedChallenge: authChallengeFromServer,
			response: assertion,
			login: harness.user.login,
			userId: harness.user.user_id
		});

		expect(verifyRes.verified).toBe(true);
		expect(verifyRes.userId).toBe(harness.user.user_id);
	});
});
