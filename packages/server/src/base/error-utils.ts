import type { ApiErrorParams } from '../apicore-server.js';

interface HttpErrorLike {
	status?: unknown;
	statusCode?: unknown;
}

export interface ApiErrorLike {
	code: number;
	message: string;
	data?: unknown;
	errors?: unknown;
}

export function guessExceptionText(error: unknown, defMsg: string = 'Unknown Error'): string {
	const msg: string[] = [];

	if (typeof error === 'string' && error.trim() !== '') {
		msg.push(error);
	} else if (error && typeof error === 'object') {
		const errorDetails = error as {
			message?: unknown;
			parent?: { message?: unknown };
		};
		if (typeof errorDetails.message === 'string' && errorDetails.message.trim() !== '') {
			msg.push(errorDetails.message);
		}
		if (
			errorDetails.parent &&
			typeof errorDetails.parent.message === 'string' &&
			errorDetails.parent.message.trim() !== ''
		) {
			msg.push(errorDetails.parent.message);
		}
	}

	return msg.length > 0 ? msg.join(' / ') : defMsg;
}

export function normalizeApiErrorParams({ code, message, data, errors }: ApiErrorParams): {
	code: number;
	message: string;
	data: unknown;
	errors: Record<string, string>;
} {
	return {
		code: typeof code === 'number' ? code : 500,
		message: guessExceptionText(message, '[Unknown error (null/undefined)]'),
		data: data !== undefined ? data : null,
		errors: errors !== undefined ? errors : {}
	};
}

export function isApiErrorLike(candidate: unknown): candidate is ApiErrorLike {
	if (!candidate || typeof candidate !== 'object') {
		return false;
	}
	const maybeError = candidate as ApiErrorLike;
	return typeof maybeError.code === 'number' && typeof maybeError.message === 'string';
}

export function asHttpStatus(error: unknown): number | null {
	if (!error || typeof error !== 'object') {
		return null;
	}
	const maybe = error as HttpErrorLike;
	const status = typeof maybe.status === 'number' ? maybe.status : maybe.statusCode;
	if (typeof status === 'number' && status >= 400 && status <= 599) {
		return status;
	}
	return null;
}
