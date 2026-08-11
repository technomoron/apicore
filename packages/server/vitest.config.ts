import { defineConfig } from 'vitest/config';

export default defineConfig({
	cacheDir: './.vitest-cache',
	test: {
		environment: 'node',
		fileParallelism: false,
		coverage: {
			exclude: ['dist/**', '**/dist/**']
		}
	}
});
