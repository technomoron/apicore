import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
	cacheDir: './.vitest-cache',
	resolve: {
		alias: {
			'@technomoron/apicore-server': path.resolve(__dirname, '../server/src/index.ts')
		}
	},
	test: {
		environment: 'node',
		include: ['tests/**/*.test.ts']
	}
});
