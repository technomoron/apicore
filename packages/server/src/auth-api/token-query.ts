import { toOptionalStringId } from './user-id.js';

import type { AuthIdentifier } from './types.js';
import type { Token } from '../token/types.js';

export type TokenIdentityQuery = Partial<Token> & {
	userId?: AuthIdentifier;
	ruid?: AuthIdentifier;
};

export function normalizeTokenIdentityQuery(query: TokenIdentityQuery): Partial<Token> {
	return {
		...query,
		userId: toOptionalStringId(query.userId),
		ruid: toOptionalStringId(query.ruid)
	};
}
