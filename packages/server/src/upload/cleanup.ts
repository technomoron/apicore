import { lstat, rm } from 'node:fs/promises';

/** Remove a file only when its modification time is older than the cleanup cutoff. */
export async function removeStaleUploadFile(filepath: string, cutoff: Date): Promise<number | null> {
	const fileStats = await lstat(filepath).catch(() => null);
	if (!fileStats || fileStats.mtime >= cutoff) {
		return null;
	}
	await rm(filepath, { force: true });
	return fileStats.size;
}
