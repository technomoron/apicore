import { TusUploadExceedsLengthError, TusUploadOffsetError } from './errors.js';

import type { TusAppendInput, TusUploadRecord } from './types.js';

export function cloneTusUploadRecord(record: TusUploadRecord): TusUploadRecord {
	return {
		...record,
		metadata: { ...record.metadata },
		createdAt: new Date(record.createdAt),
		updatedAt: new Date(record.updatedAt),
		...(record.completedAt ? { completedAt: new Date(record.completedAt) } : {})
	};
}

export function nextTusUploadOffset(record: TusUploadRecord, input: TusAppendInput): number {
	if (input.offset !== record.offset) {
		throw new TusUploadOffsetError(record.offset);
	}
	const nextOffset = record.offset + input.chunk.length;
	if (nextOffset > record.length) {
		throw new TusUploadExceedsLengthError();
	}
	return nextOffset;
}
