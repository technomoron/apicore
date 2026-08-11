import type { AuthIdentifier } from './types.js';
import type { PasskeyUserDescriptor } from '../passkey/types.js';

export type PasskeyUserLookup = { userId?: AuthIdentifier; login?: string };

export function createPasskeyUserResolver<UserAttributes>(params: {
	findUser: (identifier: AuthIdentifier | string) => Promise<UserAttributes | null>;
	mapper?: (user: UserAttributes) => PasskeyUserDescriptor;
	toDescriptor: (user: UserAttributes) => PasskeyUserDescriptor;
}): (lookup: PasskeyUserLookup) => Promise<PasskeyUserDescriptor | null> {
	return async (lookup) => {
		const found = await params.findUser(lookup.userId ?? lookup.login ?? '');
		if (!found) {
			return null;
		}
		return (params.mapper ?? params.toDescriptor)(found);
	};
}
