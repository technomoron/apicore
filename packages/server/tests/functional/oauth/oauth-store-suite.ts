import { expect, it } from 'vitest';

import type { AuthIdentifier } from '../../../src/auth-api/types.js';
import type { OAuthStore } from '../../../src/oauth/base.js';
import type { OAuthClient } from '../../../src/oauth/types.js';

interface SuiteContext {
	store: OAuthStore;
	cleanup?: () => Promise<void>;
}

type StoreFactory = () => Promise<SuiteContext>;

function sampleClient(id = 'client1'): OAuthClient {
	return {
		clientId: id,
		clientSecret: 'secret',
		redirectUris: ['https://example.com/callback'],
		scope: ['read', 'write'],
		metadata: { note: 'meta' },
		firstParty: true
	};
}

export function runOAuthStoreSuite(label: string, factory: StoreFactory): void {
	it(`${label} - clients and codes`, async () => {
		const { store, cleanup } = await factory();
		try {
			const created = await store.createClient(sampleClient());
			expect(created.clientId).toBe('client1');

			const fetched = await store.getClient('client1');
			expect(fetched?.redirectUris).toEqual(['https://example.com/callback']);
			expect(fetched?.scope).toEqual(['read', 'write']);
			expect(fetched?.hasSecret).toBe(true);

			expect(await store.verifyClientSecret('client1', 'secret')).toBe(true);
			expect(await store.verifyClientSecret('client1', 'wrong')).toBe(false);

			const code = {
				code: 'code1',
				clientId: 'client1',
				userId: 1 as AuthIdentifier,
				redirectUri: 'https://example.com/callback',
				scope: ['read'],
				expiresAt: new Date(Date.now() + 1000)
			};
			await store.createAuthCode(code);
			const consumed = await store.consumeAuthCode('code1');
			expect(consumed?.clientId).toBe('client1');
			expect(consumed?.scope).toEqual(['read']);
			expect(await store.consumeAuthCode('code1')).toBeNull();
		} finally {
			await cleanup?.();
		}
	});

	it(`${label} - does not consume expired authorization codes`, async () => {
		const { store, cleanup } = await factory();
		try {
			await store.createClient(sampleClient('client-expired'));
			await store.createAuthCode({
				code: 'code-expired',
				clientId: 'client-expired',
				userId: 1 as AuthIdentifier,
				redirectUri: 'https://example.com/callback',
				scope: ['read'],
				expiresAt: new Date(Date.now() - 1000)
			});

			expect(await store.consumeAuthCode('code-expired')).toBeNull();
			expect(await store.consumeAuthCode('code-expired')).toBeNull();
		} finally {
			await cleanup?.();
		}
	});
}
