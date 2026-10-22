import { createHmac, timingSafeEqual } from 'node:crypto';

/** RFC 6238 SHA-1 TOTP. Returns the matching counter so callers can reject replay. */
export function verifyTotp(
	secret: string,
	code: string,
	options: { time?: number; digits?: 6 | 8; period?: number; window?: number; after?: number } = {}
): number | null {
	const digits = options.digits ?? 6;
	const period = options.period ?? 30;
	const window = options.window ?? 1;
	const time = options.time ?? Date.now();
	if (
		![6, 8].includes(digits) ||
		!Number.isInteger(period) ||
		period <= 0 ||
		!Number.isInteger(window) ||
		window < 0 ||
		window > 2 ||
		!Number.isFinite(time) ||
		time < 0
	) {
		throw new Error('Invalid TOTP options');
	}
	if (!new RegExp('^[0-9]{' + digits + '}$').test(code)) return null;
	const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	const normalized = secret.toUpperCase().replace(/=+$/, '');
	if (!/^[A-Z2-7]{16,}$/.test(normalized)) throw new Error('Invalid base32 TOTP secret');
	let bits = 0;
	let value = 0;
	const bytes: number[] = [];
	for (const character of normalized) {
		value = (value << 5) | alphabet.indexOf(character);
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			bytes.push((value >>> bits) & 255);
		}
	}
	const key = Buffer.from(bytes);
	const counter = Math.floor(time / 1000 / period);
	for (let step = counter - window; step <= counter + window; step++) {
		if (step < 0 || step <= (options.after ?? -1)) continue;
		const input = Buffer.alloc(8);
		input.writeBigUInt64BE(BigInt(step));
		const digest = createHmac('sha1', key).update(input).digest();
		const offset = digest[digest.length - 1]! & 15;
		const expected = String((digest.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits).padStart(digits, '0');
		if (timingSafeEqual(Buffer.from(code), Buffer.from(expected))) return step;
	}
	return null;
}
