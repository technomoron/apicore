import {
	generateAuthenticationOptions,
	generateRegistrationOptions,
	verifyAuthenticationResponse,
	verifyRegistrationResponse
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';

import type {
	PasskeyChallenge,
	PasskeyChallengeParams,
	PasskeyChallengeRecord,
	PasskeyStorageAdapter,
	PasskeyUserDescriptor,
	PasskeyVerificationParams,
	PasskeyVerificationResult,
	PasskeyServiceConfig,
	StoredPasskeyCredential
} from './types.js';
import type { AuthIdentifier } from '../auth-api/types.js';
import type {
	AuthenticationResponseJSON,
	AuthenticatorTransportFuture,
	PublicKeyCredentialDescriptorJSON,
	RegistrationResponseJSON,
	WebAuthnCredential
} from '@simplewebauthn/server';

export type {
	CredentialDeviceType,
	PasskeyChallenge,
	PasskeyChallengeParams,
	PasskeyChallengeRecord,
	PasskeyUserDescriptor,
	PasskeyVerificationParams,
	PasskeyVerificationResult,
	PasskeyServiceConfig,
	PasskeyStorageAdapter,
	StoredPasskeyCredential
} from './types.js';

type Logger = Pick<typeof console, 'error' | 'warn'>;
const ALLOWED_TRANSPORTS: AuthenticatorTransportFuture[] = [
	'ble',
	'cable',
	'hybrid',
	'internal',
	'nfc',
	'smart-card',
	'usb'
];

function sanitizeTransports(input: unknown): AuthenticatorTransportFuture[] | undefined {
	if (!Array.isArray(input)) {
		return undefined;
	}
	const filtered = input
		.map((value) => String(value) as AuthenticatorTransportFuture)
		.filter((value): value is AuthenticatorTransportFuture => ALLOWED_TRANSPORTS.includes(value));
	return filtered.length > 0 ? filtered : undefined;
}

function toOptionalString(value: unknown): string | undefined {
	if (typeof value !== 'string') {
		return undefined;
	}
	const trimmed = value.trim();
	return trimmed.length > 0 ? trimmed : undefined;
}

function toBase64Url(buffer: Buffer): string {
	return isoBase64URL.fromBuffer(new Uint8Array(buffer));
}

function fromBase64Url(value: string): Buffer {
	return Buffer.from(isoBase64URL.toBuffer(value));
}

function toBuffer(value: ArrayBuffer | Uint8Array | Buffer): Buffer {
	if (Buffer.isBuffer(value)) {
		return value;
	}
	const view = value instanceof Uint8Array ? value : new Uint8Array(value);
	return Buffer.from(view);
}

function normalizePasskeyResponse<T extends { id: string; rawId: string }>(response: unknown): T {
	const parsed = typeof response === 'object' && response ? { ...response } : {};
	return {
		...parsed,
		id: String((parsed as { id?: unknown }).id ?? ''),
		rawId: String((parsed as { rawId?: unknown }).rawId ?? '')
	} as T;
}

export class PasskeyService {
	constructor(
		private readonly config: PasskeyServiceConfig,
		private readonly adapter: PasskeyStorageAdapter,
		private readonly logger: Logger = console
	) {}

	public async listUserCredentials(userId: AuthIdentifier): Promise<StoredPasskeyCredential[]> {
		return this.adapter.listUserCredentials(userId);
	}

	public async deleteCredential(credentialId: Buffer | string, userId?: AuthIdentifier): Promise<boolean> {
		if (userId !== undefined) {
			const credentials = await this.adapter.listUserCredentials(userId);
			const target = Buffer.isBuffer(credentialId) ? credentialId : Buffer.from(String(credentialId), 'base64');
			const owns = credentials.some((c) => {
				const stored = Buffer.isBuffer(c.credentialId)
					? c.credentialId
					: Buffer.from(String(c.credentialId), 'base64');
				return stored.equals(target);
			});
			if (!owns) return false;
		}
		return this.adapter.deleteCredential(credentialId);
	}

	public async createChallenge(params: PasskeyChallengeParams): Promise<PasskeyChallenge> {
		await this.adapter.cleanupChallenges?.(new Date());

		if (params.action === 'register') {
			return this.createRegistrationChallenge(params);
		}
		if (params.action === 'authenticate') {
			return this.createAuthenticationChallenge(params);
		}
		throw new Error(`Unsupported passkey action: ${String(params.action)}`);
	}

	public async getChallenge(challenge: string): Promise<PasskeyChallengeRecord | null> {
		if (typeof this.adapter.getChallenge !== 'function') {
			return null;
		}
		return this.adapter.getChallenge(challenge);
	}

	public async verifyResponse(params: PasskeyVerificationParams): Promise<PasskeyVerificationResult> {
		await this.adapter.cleanupChallenges?.(new Date());

		const existing = this.adapter.getChallenge ? await this.adapter.getChallenge(params.expectedChallenge) : null;
		if (existing && existing.expiresAt.getTime() <= Date.now()) {
			return { verified: false, action: existing.action };
		}

		const record = await this.adapter.consumeChallenge(params.expectedChallenge);
		if (!record) {
			return { verified: false };
		}

		if (record.expiresAt.getTime() <= Date.now()) {
			return { verified: false, action: record.action };
		}

		try {
			if (record.action === 'register') {
				return this.verifyRegistration(params, record);
			}
			if (record.action === 'authenticate') {
				return this.verifyAuthentication(params, record);
			}
		} catch (error) {
			this.logger.error?.('Passkey verification failed', error);
		}

		return { verified: false };
	}

	private async createRegistrationChallenge(params: PasskeyChallengeParams): Promise<PasskeyChallenge> {
		const user = await this.requireUser({
			userId: params.userId,
			login: params.login
		});
		const existing = await this.adapter.listUserCredentials(user.id);
		const excludeCredentials = existing.map((credential) => {
			const transports = credential.transports;
			return transports && transports.length > 0
				? { id: toBase64Url(credential.credentialId), transports }
				: { id: toBase64Url(credential.credentialId) };
		});

		const options = await generateRegistrationOptions({
			rpName: this.config.rpName,
			rpID: this.config.rpId,
			userID: Buffer.from(String(user.id)),
			userName: user.login,
			userDisplayName: user.displayName,
			excludeCredentials
		});

		const expiresAt = this.createExpiry();

		await this.adapter.saveChallenge({
			challenge: options.challenge,
			action: 'register',
			userId: user.id,
			login: user.login,
			expiresAt
		});

		return {
			challenge: options.challenge,
			expiresAt: expiresAt.toISOString(),
			userId: user.id,
			publicKey: options
		};
	}

	private async createAuthenticationChallenge(params: PasskeyChallengeParams): Promise<PasskeyChallenge> {
		const hasIdentifier = params.userId !== undefined || toOptionalString(params.login) !== undefined;
		const user = hasIdentifier
			? await this.adapter.resolveUser({
					userId: params.userId,
					login: params.login
				})
			: null;
		const credentials = user ? await this.adapter.listUserCredentials(user.id) : [];
		const allowCredentials: PublicKeyCredentialDescriptorJSON[] = credentials.map((credential) => {
			const transports = sanitizeTransports(credential.transports);
			return transports && transports.length > 0
				? {
						type: 'public-key',
						id: toBase64Url(credential.credentialId),
						transports
					}
				: {
						type: 'public-key',
						id: toBase64Url(credential.credentialId)
					};
		});

		const options = await generateAuthenticationOptions({
			allowCredentials,
			userVerification: this.config.userVerification,
			rpID: this.config.rpId
		});

		const expiresAt = this.createExpiry();

		await this.adapter.saveChallenge({
			challenge: options.challenge,
			action: 'authenticate',
			userId: user?.id,
			login: user?.login,
			expiresAt
		});

		return {
			challenge: options.challenge,
			expiresAt: expiresAt.toISOString(),
			userId: user?.id,
			publicKey: options
		};
	}

	private async verifyRegistration(
		params: PasskeyVerificationParams,
		record: PasskeyChallengeRecord
	): Promise<PasskeyVerificationResult> {
		const response = normalizePasskeyResponse<RegistrationResponseJSON>(params.response);

		const user = await this.requireUser({
			userId: record.userId,
			login: record.login
		});

		const result = await verifyRegistrationResponse({
			response,
			expectedChallenge: record.challenge,
			expectedOrigin: this.config.origins,
			expectedRPID: this.config.rpId,
			requireUserVerification: this.requireUserVerification()
		});

		if (!result.verified || !result.registrationInfo) {
			if (!result.verified) {
				const err = (result as { error?: unknown }).error ?? result;
				this.logger.error?.('Passkey registration verification failed', err);
			}
			return { verified: false, action: 'register' };
		}

		const { credential, credentialBackedUp, credentialDeviceType } = result.registrationInfo;
		const credentialId = fromBase64Url(credential.id);
		const publicKey = toBuffer(credential.publicKey);
		if (credentialId.length === 0) {
			return {
				verified: false,
				action: 'register',
				message: 'Missing credential id in registration response'
			};
		}
		if (publicKey.length === 0) {
			return {
				verified: false,
				action: 'register',
				message: 'Missing public key in registration response'
			};
		}
		await this.adapter.saveCredential({
			userId: user.id,
			credentialId,
			publicKey,
			counter: credential.counter,
			transports: sanitizeTransports(credential.transports),
			backedUp: credentialBackedUp,
			deviceType: credentialDeviceType,
			label: toOptionalString(params.label),
			createdDomain: toOptionalString(params.domain),
			createdUserAgent: toOptionalString(params.userAgent),
			createdBrowser: toOptionalString(params.browser),
			createdOs: toOptionalString(params.os),
			createdDevice: toOptionalString(params.device),
			createdIp: toOptionalString(params.ip)
		});

		return {
			verified: true,
			action: 'register',
			credentialId: credential.id,
			userId: user.id,
			login: user.login
		};
	}

	private async verifyAuthentication(
		params: PasskeyVerificationParams,
		record: PasskeyChallengeRecord
	): Promise<PasskeyVerificationResult> {
		const response = normalizePasskeyResponse<AuthenticationResponseJSON>(params.response);

		const credential = await this.adapter.findCredentialById(fromBase64Url(response.id));
		if (!credential) {
			return { verified: false, action: 'authenticate' };
		}

		const user = await this.requireUser({
			userId: credential.userId,
			login: record.login
		});
		const storedAuthData: WebAuthnCredential = {
			id: toBase64Url(credential.credentialId),
			publicKey: new Uint8Array(toBuffer(credential.publicKey)),
			counter: credential.counter,
			transports: credential.transports ?? undefined
			// simplewebauthn accepts either Uint8Array or Buffer; ensure Buffer
			// see https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/server/src/authentication/verifyAuthenticationResponse.ts
		};

		const result = await verifyAuthenticationResponse({
			response,
			expectedChallenge: record.challenge,
			expectedOrigin: this.config.origins,
			expectedRPID: this.config.rpId,
			credential: storedAuthData,
			requireUserVerification: this.requireUserVerification()
		});

		if (!result.verified) {
			const err = (result as { error?: unknown }).error ?? result;
			this.logger.error?.('Passkey authentication verification failed', err);
			return { verified: false, action: 'authenticate' };
		}

		await this.adapter.updateCredentialCounter(credential.credentialId, result.authenticationInfo.newCounter);

		return {
			verified: true,
			action: 'authenticate',
			userId: user.id,
			login: user.login
		};
	}

	private async requireUser(params: { userId?: AuthIdentifier; login?: string }): Promise<PasskeyUserDescriptor> {
		const user = await this.adapter.resolveUser(params);
		if (!user) {
			throw new Error('User not found');
		}
		return user;
	}

	private createExpiry(): Date {
		return new Date(Date.now() + this.config.timeoutMs);
	}

	private requireUserVerification(): boolean {
		return this.config.userVerification !== 'discouraged';
	}
}
