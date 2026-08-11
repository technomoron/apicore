import { isoBase64URL } from '@simplewebauthn/server/helpers';

import type {
	AuthenticationResponseJSON,
	PublicKeyCredentialCreationOptionsJSON,
	PublicKeyCredentialRequestOptionsJSON,
	RegistrationResponseJSON
} from '@simplewebauthn/server';

interface FakePasskeyClientOptions {
	rpId: string;
	origin?: string;
	userId: number | string;
	credentialId?: Buffer | string;
	transports?: string[];
}

export class FakePasskeyClient {
	private readonly rpId: string;
	private readonly origin?: string;
	private readonly userHandle: string;
	private credentialId: string;
	private readonly transports?: string[];

	constructor(options: FakePasskeyClientOptions) {
		this.rpId = options.rpId;
		this.origin = options.origin;
		this.userHandle = isoBase64URL.fromBuffer(Buffer.from(String(options.userId)));
		this.credentialId =
			typeof options.credentialId === 'string'
				? options.credentialId
				: isoBase64URL.fromBuffer(options.credentialId ?? Buffer.from('fake-cred'));
		this.transports = options.transports;
	}

	public createRegistrationResponse(payload: Record<string, unknown>): RegistrationResponseJSON {
		const options = payload.publicKey as PublicKeyCredentialCreationOptionsJSON | undefined;
		if (!options) {
			throw new Error('publicKey is required to create a registration response');
		}

		if (options.rp?.id && options.rp.id !== this.rpId) {
			throw new Error(`rp.id mismatch: expected ${this.rpId}, got ${options.rp.id}`);
		}

		if (typeof options.challenge !== 'string' || options.challenge.length === 0) {
			throw new Error('registration challenge must be a non-empty string');
		}

		// Simulate browser issuing a new credential; use provided credentialId if supplied.
		const id = this.credentialId;

		return {
			id,
			rawId: id,
			response: {
				attestationObject: 'attestation-data',
				clientDataJSON: 'client-data'
			},
			type: 'public-key',
			clientExtensionResults: {}
		};
	}

	public createAuthenticationResponse(payload: Record<string, unknown>): AuthenticationResponseJSON {
		const options = payload.publicKey as PublicKeyCredentialRequestOptionsJSON | undefined;
		if (!options) {
			throw new Error('publicKey is required to create an authentication response');
		}

		if (options.rpId && options.rpId !== this.rpId) {
			throw new Error(`rpId mismatch: expected ${this.rpId}, got ${options.rpId}`);
		}

		if (typeof options.challenge !== 'string' || options.challenge.length === 0) {
			throw new Error('authentication challenge must be a non-empty string');
		}

		const allowCredentials = options.allowCredentials ?? [];
		const credential = allowCredentials[0];
		if (!credential) {
			throw new Error('authentication options must include allowCredentials');
		}
		if (credential.id !== this.credentialId) {
			throw new Error(`credential id mismatch: expected ${this.credentialId}, got ${credential.id}`);
		}
		if (this.transports && credential.transports) {
			const hasOverlap = credential.transports.some((entry) => this.transports?.includes(entry));
			if (!hasOverlap) {
				throw new Error('credential transports do not overlap with client transports');
			}
		}

		return {
			id: credential.id,
			rawId: credential.id,
			response: {
				authenticatorData: 'auth-data',
				clientDataJSON: 'client-data',
				signature: 'signature',
				userHandle: this.userHandle
			},
			type: 'public-key',
			clientExtensionResults: {}
		};
	}
}
