export type RateLimitDecision = { allowed: boolean; retryAfterSec: number };

export class FixedWindowRateLimiter {
	private readonly buckets = new Map<string, { windowStartMs: number; count: number }>();

	constructor(private readonly maxKeys = 10_000) {}

	check(key: string, max: number, windowMs: number): RateLimitDecision {
		if (!key || max <= 0 || windowMs <= 0) {
			return { allowed: true, retryAfterSec: 0 };
		}
		const now = Date.now();
		const bucket = this.buckets.get(key);
		if (!bucket || now - bucket.windowStartMs >= windowMs) {
			this.buckets.delete(key);
			this.buckets.set(key, { windowStartMs: now, count: 1 });
			this.prune();
			return { allowed: true, retryAfterSec: 0 };
		}

		bucket.count += 1;
		// Refresh insertion order to keep active entries at the end for pruning.
		this.buckets.delete(key);
		this.buckets.set(key, bucket);

		if (bucket.count <= max) {
			return { allowed: true, retryAfterSec: 0 };
		}

		const retryAfterSec = Math.max(1, Math.ceil((bucket.windowStartMs + windowMs - now) / 1000));
		return { allowed: false, retryAfterSec };
	}

	private prune() {
		while (this.buckets.size > this.maxKeys) {
			const oldest = this.buckets.keys().next().value as string | undefined;
			if (!oldest) {
				break;
			}
			this.buckets.delete(oldest);
		}
	}
}
