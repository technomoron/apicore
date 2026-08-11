const { copyFileSync } = require('node:fs');
const { resolve } = require('node:path');

const root = resolve(__dirname, '..');
const sharedFiles = [
	{
		source: resolve(root, 'packages/common/types.ts'),
		targets: [resolve(root, 'packages/client/src/common.ts'), resolve(root, 'packages/server/src/common.ts')]
	},
	{
		source: resolve(root, 'packages/common/debug.ts'),
		targets: [resolve(root, 'packages/client/src/debug.ts'), resolve(root, 'packages/server/src/base/debug.ts')]
	}
];

for (const sharedFile of sharedFiles) {
	for (const target of sharedFile.targets) {
		copyFileSync(sharedFile.source, target);
	}
}
