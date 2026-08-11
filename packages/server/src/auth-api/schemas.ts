import { type JsonSchema } from '../base/json-schema.js';

/**
 * JSON Schema definitions for auth module routes.
 * These are the runtime validation source-of-truth; TypeScript interfaces
 * in auth-module.ts remain for handler-internal typing only.
 */

/* ------------------------------------------------------------------ */
/*  Shared fragments                                                   */
/* ------------------------------------------------------------------ */

const tokenMetadataProperties = {
	domain: { type: 'string' },
	fingerprint: { type: 'string' },
	label: { type: 'string' },
	browser: { type: 'string' },
	device: { type: 'string' },
	ip: { type: 'string' },
	os: { type: 'string' }
} as const;

const keepSessionProperty = {
	keepSession: { type: ['boolean', 'number', 'string'] }
} as const;

function authIdentifierProperty(name: string): Record<string, { type: string[] }> {
	return { [name]: { type: ['string', 'number'] } };
}

/* ------------------------------------------------------------------ */
/*  Auth route schemas                                                 */
/* ------------------------------------------------------------------ */

export const loginBodySchema: JsonSchema = {
	type: 'object',
	required: ['login', 'password'],
	properties: {
		login: { type: 'string', minLength: 1 },
		password: { type: 'string', minLength: 1 },
		...tokenMetadataProperties,
		...keepSessionProperty
	},
	additionalProperties: true
};

export const refreshBodySchema: JsonSchema = {
	type: 'object',
	properties: {
		refreshToken: { type: 'string' },
		domain: { type: 'string' },
		fingerprint: { type: 'string' },
		label: { type: 'string' },
		...keepSessionProperty
	},
	additionalProperties: false
};

export const logoutBodySchema: JsonSchema = {
	type: 'object',
	properties: {
		token: { type: 'string' },
		refreshToken: { type: 'string' }
	},
	additionalProperties: false
};

export const sessionParamsSchema: JsonSchema = {
	type: 'object',
	required: ['sessionId'],
	properties: {
		sessionId: { type: 'string', minLength: 1 }
	},
	additionalProperties: false
};

/* ------------------------------------------------------------------ */
/*  Passkey schemas                                                    */
/* ------------------------------------------------------------------ */

export const passkeyChallengeBodySchema: JsonSchema = {
	type: 'object',
	required: ['action'],
	properties: {
		action: { type: 'string', enum: ['register', 'authenticate'] },
		login: { type: 'string' },
		...authIdentifierProperty('userId')
	},
	additionalProperties: false
};

export const passkeyVerifyBodySchema: JsonSchema = {
	type: 'object',
	required: ['expectedChallenge', 'response'],
	properties: {
		expectedChallenge: { type: 'string' },
		response: { type: 'object' },
		login: { type: 'string' },
		...authIdentifierProperty('userId'),
		userAgent: { type: 'string' },
		...tokenMetadataProperties,
		...keepSessionProperty
	},
	additionalProperties: true
};

export const passkeyCredentialParamsSchema: JsonSchema = {
	type: 'object',
	required: ['credentialId'],
	properties: {
		credentialId: { type: 'string', minLength: 1 }
	},
	additionalProperties: false
};

/* ------------------------------------------------------------------ */
/*  Impersonation schemas                                              */
/* ------------------------------------------------------------------ */

export const impersonateBodySchema: JsonSchema = {
	type: 'object',
	properties: {
		...authIdentifierProperty('userId'),
		login: { type: 'string' },
		...tokenMetadataProperties,
		...keepSessionProperty,
		clientId: { type: 'string' },
		scope: {},
		loginType: { type: 'string' }
	},
	additionalProperties: true
};

export const deleteImpersonationQuerySchema: JsonSchema = {
	type: 'object',
	properties: {
		...tokenMetadataProperties,
		...keepSessionProperty,
		clientId: { type: 'string' },
		scope: {},
		loginType: { type: 'string' }
	},
	additionalProperties: false
};

/* ------------------------------------------------------------------ */
/*  OAuth schemas                                                      */
/* ------------------------------------------------------------------ */

export const oauthProviderParamsSchema: JsonSchema = {
	type: 'object',
	required: ['provider'],
	properties: {
		provider: { type: 'string', minLength: 1 }
	},
	additionalProperties: false
};

export const oauthStartBodySchema: JsonSchema = {
	type: 'object',
	properties: {
		redirectUri: { type: 'string' },
		scope: {},
		state: { type: 'string' },
		extras: { type: 'object' }
	},
	additionalProperties: true
};

export const oauthAuthorizeBodySchema: JsonSchema = {
	type: 'object',
	required: ['clientId', 'redirectUri'],
	properties: {
		clientId: { type: 'string', minLength: 1 },
		redirectUri: { type: 'string', minLength: 1 },
		scope: {},
		state: { type: 'string' },
		codeChallenge: { type: 'string' },
		codeChallengeMethod: { type: 'string' },
		login: { type: 'string' },
		password: { type: 'string' },
		refreshToken: { type: 'string' }
	},
	additionalProperties: false
};

export const oauthTokenBodySchema: JsonSchema = {
	type: 'object',
	required: ['grant_type'],
	properties: {
		grant_type: {
			type: 'string',
			enum: ['authorization_code', 'refresh_token']
		},
		code: { type: 'string' },
		redirect_uri: { type: 'string' },
		code_verifier: { type: 'string' },
		client_id: { type: 'string' },
		client_secret: { type: 'string' },
		refresh_token: { type: 'string' },
		scope: { type: 'string' }
	},
	additionalProperties: false
};
