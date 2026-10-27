export interface SecurityEventRecord extends Record<string, unknown> {
	ts: string;
	event: string;
}

export type SecurityEventSink = (record: SecurityEventRecord) => unknown | Promise<unknown>;

export class SecurityEventService {
	// Keep audit emission independent from enforcement and application logging.
	constructor(private readonly sink?: SecurityEventSink) {}

	// Emit caller-selected safe fields with authoritative event and timestamp values.
	public async report(event: string, fields: Record<string, unknown> = {}): Promise<void> {
		await this.sink?.({ ...fields, ts: new Date().toISOString(), event });
	}
}
