#!/usr/bin/env node

const { writeFileSync } = require('node:fs');
const path = require('node:path');

const commonJsDir = path.resolve(__dirname, '..', 'dist', 'cjs');

writeFileSync(path.join(commonJsDir, 'package.json'), '{\n\t"type": "commonjs"\n}\n', 'utf8');
