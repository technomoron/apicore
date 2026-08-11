export const DEBUG_REDACTED_VALUE = '[REDACTED]';

interface DebugValueSummary {
	handled: true;
	value: unknown;
}

export interface DebugValueRedactionOptions {
	sensitiveKeys: ReadonlySet<string>;
	isRecord: (value: unknown) => value is Record<string, unknown>;
	summarize?: (value: unknown) => DebugValueSummary | undefined;
}

function redactDebugArray(value: unknown[], options: DebugValueRedactionOptions, seen: WeakSet<object>): unknown[] {
	return value.map((entry) => redactDebugValue(entry, options, seen));
}

function redactDebugRecord(
	value: Record<string, unknown>,
	options: DebugValueRedactionOptions,
	seen: WeakSet<object>
): unknown {
	if (seen.has(value)) {
		return '[Circular]';
	}
	seen.add(value);
	const out: Record<string, unknown> = {};
	for (const [key, entry] of Object.entries(value)) {
		out[key] = options.sensitiveKeys.has(key.toLowerCase())
			? DEBUG_REDACTED_VALUE
			: redactDebugValue(entry, options, seen);
	}
	seen.delete(value);
	return out;
}

export function redactDebugValue(
	value: unknown,
	options: DebugValueRedactionOptions,
	seen: WeakSet<object> = new WeakSet()
): unknown {
	if (value === null || value === undefined) {
		return value;
	}
	if (Array.isArray(value)) {
		return redactDebugArray(value, options, seen);
	}
	const summary = options.summarize?.(value);
	if (summary?.handled) {
		return summary.value;
	}
	if (!options.isRecord(value)) {
		return value;
	}
	return redactDebugRecord(value, options, seen);
}
