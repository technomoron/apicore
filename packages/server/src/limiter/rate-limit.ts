export interface RateLimitRule {
	limit: number;
	windowMs: number;
}

export interface RateLimitDecision {
	allowed: boolean;
	limit: number;
	remaining: number;
	retryAfterSec: number;
}

export interface RateLimitStore {
	consume(key: string, rule: RateLimitRule, cost?: number): Promise<RateLimitDecision>;
}

export interface RateLimitPolicy extends RateLimitRule {
	identity: 'ip' | 'user';
}

export interface RateLimitConfig {
	policies?: Record<string, RateLimitPolicy>;
	global?: string;
	store?: RateLimitStore;
	/** Process-local memory bound when no custom store is provided. Defaults to 10,000. */
	maxKeys?: number;
}

// Reject invalid quota values before mutating counters or calling a backend.
function positiveInteger(value: number, name: string): void {
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new TypeError(`${name} must be a positive safe integer`);
	}
}

// Require nonempty canonical identities and policy names.
function nonemptyString(value: string, name: string): void {
	if (typeof value !== 'string' || value.trim() === '') {
		throw new TypeError(`${name} must be a nonempty string`);
	}
}

export class MemoryRateLimitStore implements RateLimitStore {
	private readonly buckets = new Map<string, { expiresAt: number; used: number }>();

	// Bound memory independently of the number of identities supplied.
	constructor(private readonly maxKeys = 10_000) {
		positiveInteger(maxKeys, 'maxKeys');
	}

	// Consume attempts in a fixed window and refresh least-recently-used eviction order.
	public async consume(key: string, { limit, windowMs }: RateLimitRule, cost = 1): Promise<RateLimitDecision> {
		nonemptyString(key, 'key');
		positiveInteger(limit, 'limit');
		positiveInteger(windowMs, 'windowMs');
		positiveInteger(cost, 'cost');
		const now = Date.now();
		let bucket = this.buckets.get(key);
		if (!bucket || now >= bucket.expiresAt) {
			bucket = { expiresAt: now + windowMs, used: 0 };
		}
		bucket.used = Math.min(Number.MAX_SAFE_INTEGER + 1, bucket.used + cost);
		this.buckets.delete(key);
		this.buckets.set(key, bucket);
		if (this.buckets.size > this.maxKeys) {
			this.buckets.delete(this.buckets.keys().next().value!);
		}
		const allowed = bucket.used <= limit;
		return {
			allowed,
			limit,
			remaining: Math.max(0, limit - bucket.used),
			retryAfterSec: allowed ? 0 : Math.max(1, Math.ceil((bucket.expiresAt - now) / 1000))
		};
	}
}

export class RateLimitService {
	private readonly policies = new Map<string, Readonly<RateLimitPolicy>>();
	private readonly store: RateLimitStore;

	// Validate and snapshot policies while accepting any asynchronous store implementation.
	constructor(config: RateLimitConfig = {}) {
		for (const [name, policy] of Object.entries(config.policies ?? {})) {
			nonemptyString(name, 'policyName');
			positiveInteger(policy.limit, 'limit');
			positiveInteger(policy.windowMs, 'windowMs');
			if (policy.identity !== 'ip' && policy.identity !== 'user') {
				throw new TypeError(`Invalid identity for rate limit policy: ${name}`);
			}
			this.policies.set(name, Object.freeze({ ...policy }));
		}
		this.store = config.store ?? new MemoryRateLimitStore(config.maxKeys);
		if (config.global !== undefined && this.getPolicy(config.global).identity !== 'ip') {
			throw new TypeError('Global rate limit policies must use IP identity');
		}
	}

	// Resolve a configured policy or reject an unknown name.
	public getPolicy(name: string): Readonly<RateLimitPolicy> {
		nonemptyString(name, 'policyName');
		const policy = this.policies.get(name);
		if (!policy) {
			throw new Error(`Unknown rate limit policy: ${name}`);
		}
		return policy;
	}

	// Namespace trusted canonical identities by policy without delimiter collisions.
	public async consume(policyName: string, identity: string, cost = 1): Promise<RateLimitDecision> {
		const policy = this.getPolicy(policyName);
		nonemptyString(identity, 'identity');
		positiveInteger(cost, 'cost');
		return this.store.consume(
			JSON.stringify([policyName, identity]),
			{ limit: policy.limit, windowMs: policy.windowMs },
			cost
		);
	}
}
