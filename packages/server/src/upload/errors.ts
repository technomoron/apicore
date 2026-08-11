export class TusUploadOffsetError extends Error {
	public readonly currentOffset: number;

	constructor(currentOffset: number) {
		super('Upload offset does not match current offset');
		this.currentOffset = currentOffset;
	}
}

export class TusUploadExceedsLengthError extends Error {
	constructor() {
		super('Upload exceeds declared length');
	}
}

export class TusUploadCapacityError extends Error {
	constructor(message: string) {
		super(message);
	}
}
