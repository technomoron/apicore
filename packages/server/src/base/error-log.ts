import { randomBytes } from 'node:crypto';
import { appendFile } from 'node:fs/promises';

// Generate a uniform 12-character ID using Nano ID's URL-safe alphabet.
export function createErrorId(): string {
	return randomBytes(9).toString('base64url');
}

// Remove credentials from free-form diagnostic messages and URLs.
function redactText(value: string, secrets: string[]): string {
	for (const secret of secrets) {
		if (secret) {
			value = value.split(secret).join('[REDACTED]');
		}
	}
	return value
		.replace(/(\b(?:Bearer|Basic)\s+)[^\s,;"']+/gi, '$1[REDACTED]')
		.replace(/(\b[a-z][a-z\d+.-]*:\/\/)[^\s/@]+@/gi, '$1[REDACTED]@')
		.replace(
			/(["']?(?:password|passwd|pwd|secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|authorization|cookie|set-cookie)["']?\s*[:=]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s,;&]+)/gi,
			'$1[REDACTED]'
		);
}

// Preserve error diagnostics while redacting credential fields and handling cycles.
function diagnostic(value: unknown, secrets: string[], seen = new WeakSet<object>()): unknown {
	if (typeof value === 'string') {
		return redactText(value, secrets);
	}
	if (value === null || typeof value !== 'object') {
		return typeof value === 'bigint' ? String(value) : value;
	}
	if (seen.has(value)) {
		return '[Circular]';
	}
	seen.add(value);
	if (Array.isArray(value)) {
		return value.map((entry) => diagnostic(entry, secrets, seen));
	}
	const result: Record<string, unknown> = {};
	const fields = new Set([
		...Object.getOwnPropertyNames(value),
		...(value instanceof Error ? ['name', 'message', 'stack', 'cause'] : [])
	]);
	for (const key of fields) {
		if (/password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie/i.test(key)) {
			result[key] = '[REDACTED]';
			continue;
		}
		try {
			result[key] = diagnostic((value as Record<string, unknown>)[key], secrets, seen);
		} catch {
			result[key] = '[Unavailable]';
		}
	}
	return result;
}

// Append one JSON line; retain redacted diagnostics on stderr if the file is unavailable.
export function logError(
	appName: string,
	errorId: string,
	context: string,
	cause: unknown,
	secrets: string[],
	logFile?: string
): void {
	const safeAppName = appName.replace(/[^a-zA-Z0-9_-]/g, '_') || 'app';
	let error: unknown;
	try {
		error = diagnostic(cause, secrets);
	} catch {
		error = '[Unavailable]';
	}
	const line = JSON.stringify({
		time: new Date().toISOString(),
		appName: safeAppName,
		pid: process.pid,
		errorId,
		context,
		error
	});
	void appendFile(logFile ?? `/var/log/apicore-${safeAppName}.log`, `${line}\n`, { mode: 0o600 }).catch(() => {
		console.error(line);
	});
}
