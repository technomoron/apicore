#!/usr/bin/env node

const { readFileSync, writeFileSync } = require('node:fs');
const path = require('node:path');

const packageRoot = path.resolve(__dirname, '..');
const packageJson = JSON.parse(readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
const outputPath = path.join(packageRoot, 'docs', 'swagger', 'openapi.json');
const document = JSON.parse(readFileSync(outputPath, 'utf8'));

const bearerSecurity = [
	{ accessTokenBearer: [] },
	{ accessTokenCookie: [] },
	{ apiKeyBearer: [] }
];

const nullEnvelopeSchema = {
	allOf: [
		{ $ref: '#/components/schemas/ApiResponse' },
		{
			type: 'object',
			properties: { data: { type: 'null' } },
			required: ['data']
		}
	]
};

const jsonError = (description) => ({
	description,
	content: {
		'application/json': {
			schema: nullEnvelopeSchema
		}
	}
});

const tusResponseHeaders = {
	'Tus-Resumable': {
		description: 'TUS protocol version.',
		schema: { type: 'string' }
	},
	'Upload-Expires': {
		description: 'Expiry time for an incomplete upload.',
		schema: { type: 'string', format: 'http-date' }
	}
};

const uploadIdParameter = {
	name: 'uploadId',
	in: 'path',
	required: true,
	description: 'Opaque upload identifier returned in the Location header.',
	schema: { type: 'string' }
};

const tusResumableParameter = {
	name: 'Tus-Resumable',
	in: 'header',
	required: true,
	description: 'TUS protocol version. Use 1.0.0.',
	schema: { type: 'string', enum: ['1.0.0'] }
};

document.info.version = packageJson.version;
document.components.securitySchemes.requestSignature = {
	type: 'apiKey',
	in: 'header',
	name: 'X-ApiCore-Signature',
	description:
		'HMAC or custom request signature. The default HMAC signer also requires X-ApiCore-Timestamp. Runtime route policy determines which operations require signing.'
};

for (const [pathName, method] of [
	['/api/auth/v1/me', 'get'],
	['/api/auth/v1/me/sessions', 'get'],
	['/api/auth/v1/me/sessions/{sessionId}', 'delete']
]) {
	document.paths[pathName][method].security = bearerSecurity;
}

const schemas = document.components.schemas;
schemas.LogoutRequest.properties.refreshToken = {
	type: 'string',
	description: 'Refresh token alternative to token; falls back to the configured refresh cookie when omitted.',
	nullable: true
};
schemas.OAuthAuthorizeRequest.properties.refreshToken = {
	type: 'string',
	description: 'Refresh token alternative to the configured refresh cookie.',
	nullable: true
};
document.paths['/api/auth/v1/oauth2/authorize'].post.description =
	'Auth: optional. Issues an authorization code for a registered redirect URI. Public clients must use PKCE; S256 is the secure default. Requested scopes must be allowed by the client record.';
schemas.OAuthTokenRequest.properties.grant_type.enum = ['authorization_code', 'refresh_token'];
schemas.OAuthTokenRequest.properties.scope = {
	type: 'string',
	description: 'Space-delimited scopes requested for the replacement token.',
	nullable: true
};
schemas.ApiOAuthTokenRes = {
	type: 'object',
	description: 'OAuth access and refresh token response.',
	properties: {
		access_token: { type: 'string' },
		refresh_token: { type: 'string' },
		token_type: { type: 'string', enum: ['Bearer'] },
		expires_in: { type: 'integer' },
		scope: { type: 'string' },
		client_id: { type: 'string' }
	},
	required: ['access_token', 'refresh_token', 'token_type', 'expires_in', 'scope', 'client_id'],
	additionalProperties: false
};
schemas.ApiPingRes.required = [
	'success',
	'status',
	'apiVersion',
	'minClientVersion',
	'uptimeSec',
	'startedAt',
	'timestamp'
];

document.paths['/api/v1/upload'] = {
	options: {
		tags: ['base'],
		operationId: 'getTusCapabilities',
		summary: 'Read TUS capabilities',
		description: 'Auth: none. Returns protocol limits and supported TUS extensions in response headers.',
		security: [],
		responses: {
			204: {
				description: 'TUS capabilities returned in headers.',
				headers: {
					'Tus-Resumable': tusResponseHeaders['Tus-Resumable'],
					'Tus-Version': {
						description: 'Supported TUS versions.',
						schema: { type: 'string' }
					},
					'Tus-Extension': {
						description: 'Supported TUS extensions.',
						schema: { type: 'string' }
					},
					'Tus-Max-Size': {
						description: 'Maximum upload size in bytes.',
						schema: { type: 'integer' }
					}
				}
			}
		}
	},
	post: {
		tags: ['base'],
		operationId: 'createTusUpload',
		summary: 'Create a resumable upload',
		description:
			'Auth: required. Creates an incomplete upload after validating its declared size and client-supplied metadata.',
		security: bearerSecurity,
		parameters: [
			tusResumableParameter,
			{
				name: 'Upload-Length',
				in: 'header',
				required: true,
				description: 'Total upload size in bytes.',
				schema: { type: 'integer', minimum: 1 }
			},
			{
				name: 'Upload-Metadata',
				in: 'header',
				required: false,
				description: 'Comma-separated TUS metadata values.',
				schema: { type: 'string' }
			}
		],
		responses: {
			201: {
				description: 'Upload created. The response has no body.',
				headers: {
					Location: {
						description: 'URL for subsequent HEAD, PATCH, and DELETE requests.',
						schema: { type: 'string' }
					},
					'Upload-Offset': {
						description: 'Initial upload offset.',
						schema: { type: 'integer' }
					},
					...tusResponseHeaders
				}
			},
			400: jsonError('Invalid TUS headers or upload length.'),
			401: jsonError('Authentication required.'),
			403: jsonError('Authenticated user is not allowed to create the upload.'),
			413: jsonError('Declared upload size exceeds the configured limit.'),
			507: jsonError('Upload storage has insufficient capacity.')
		}
	}
};

document.paths['/api/v1/upload/{uploadId}'] = {
	head: {
		tags: ['base'],
		operationId: 'inspectTusUpload',
		summary: 'Read resumable upload state',
		description: 'Auth: required. Returns the current offset and declared size in response headers.',
		security: bearerSecurity,
		parameters: [uploadIdParameter, tusResumableParameter],
		responses: {
			200: {
				description: 'Upload state returned in headers. The response has no body.',
				headers: {
					'Upload-Offset': {
						description: 'Current upload offset in bytes.',
						schema: { type: 'integer' }
					},
					'Upload-Length': {
						description: 'Declared total upload size in bytes.',
						schema: { type: 'integer' }
					},
					...tusResponseHeaders
				}
			},
			401: jsonError('Authentication required.'),
			403: jsonError('Upload belongs to another user.'),
			404: { description: 'Upload not found. The response has no body.' },
			410: { description: 'Incomplete upload expired. The response has no body.' }
		}
	},
	patch: {
		tags: ['base'],
		operationId: 'appendTusUpload',
		summary: 'Append a resumable upload chunk',
		description: 'Auth: required. Appends one binary chunk at the current upload offset.',
		security: bearerSecurity,
		parameters: [
			uploadIdParameter,
			tusResumableParameter,
			{
				name: 'Upload-Offset',
				in: 'header',
				required: true,
				description: 'Expected current upload offset in bytes.',
				schema: { type: 'integer', minimum: 0 }
			}
		],
		requestBody: {
			required: true,
			content: {
				'application/offset+octet-stream': {
					schema: { type: 'string', format: 'binary' }
				}
			}
		},
		responses: {
			204: {
				description: 'Chunk accepted. The response has no body.',
				headers: {
					'Upload-Offset': {
						description: 'Updated upload offset in bytes.',
						schema: { type: 'integer' }
					},
					...tusResponseHeaders
				}
			},
			400: jsonError('Invalid TUS headers or chunk body.'),
			401: jsonError('Authentication required.'),
			403: jsonError('Upload belongs to another user.'),
			404: { description: 'Upload not found. The response has no body.' },
			409: { description: 'Upload offset mismatch. The response has no body.' },
			410: { description: 'Incomplete upload expired. The response has no body.' },
			413: jsonError('Chunk exceeds the configured chunk or upload limit.'),
			507: jsonError('Upload storage has insufficient capacity.')
		}
	},
	delete: {
		tags: ['base'],
		operationId: 'deleteTusUpload',
		summary: 'Delete a resumable upload',
		description: 'Auth: required. Deletes an upload when the configured store supports termination.',
		security: bearerSecurity,
		parameters: [uploadIdParameter, tusResumableParameter],
		responses: {
			204: { description: 'Upload deleted. The response has no body.' },
			401: jsonError('Authentication required.'),
			403: jsonError('Upload belongs to another user.'),
			404: { description: 'Upload not found. The response has no body.' },
			405: { description: 'The configured store does not support deletion. The response has no body.' },
			410: { description: 'Incomplete upload expired. The response has no body.' }
		}
	}
};

function formatJson(value, depth = 0) {
	if (Array.isArray(value)) {
		if (value.length === 0 || value.every((entry) => entry === null || typeof entry !== 'object')) {
			return JSON.stringify(value);
		}
		const indent = '\t'.repeat(depth);
		const childIndent = '\t'.repeat(depth + 1);
		return `[\n${value.map((entry) => `${childIndent}${formatJson(entry, depth + 1)}`).join(',\n')}\n${indent}]`;
	}
	if (value && typeof value === 'object') {
		const entries = Object.entries(value);
		if (entries.length === 0) {
			return '{}';
		}
		const indent = '\t'.repeat(depth);
		const childIndent = '\t'.repeat(depth + 1);
		return `{\n${entries
			.map(([key, entry]) => `${childIndent}${JSON.stringify(key)}: ${formatJson(entry, depth + 1)}`)
			.join(',\n')}\n${indent}}`;
	}
	return JSON.stringify(value);
}

writeFileSync(outputPath, `${formatJson(document)}\n`, 'utf8');
