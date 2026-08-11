import js from '@eslint/js';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';
import eslintConfigPrettier from 'eslint-config-prettier/flat';
import pluginImportX from 'eslint-plugin-import-x';
import globals from 'globals';
import * as jsoncParser from 'jsonc-eslint-parser';

// Vue and Markdown support is optional. The installer adds `eslint-plugin-vue`
// and `@eslint/markdown` only when those features are enabled, and removes them
// again when they are turned off, so the presence of the package is what
// switches the matching rules on or off here.

const JS_FILE_GLOBS = ['**/*.{js,mjs,cjs,jsx}'];
const TS_FILE_GLOBS = ['**/*.{ts,mts,cts,tsx}'];
const VUE_FILE_GLOBS = ['**/*.vue'];
const SCRIPT_FILE_GLOBS = ['**/*.{js,mjs,cjs,jsx,ts,mts,cts,tsx,vue}'];
const TS_LIKE_FILE_GLOBS = ['**/*.{ts,mts,cts,tsx,vue}'];

const { hasVueSupport, pluginVue, vueTypeScriptConfigs } = await loadVueSupport();
const scopedVueTypeScriptConfigs = hasVueSupport ? scopeVueConfigs(vueTypeScriptConfigs).map(stripTypeScriptPlugin) : [];
const vueSpecificBlocks = hasVueSupport
	? [
			...scopedVueTypeScriptConfigs,
			{
				files: VUE_FILE_GLOBS,
				plugins: {
					vue: pluginVue
				},
				rules: {
					'vue/html-indent': 'off', // Let Prettier handle indentation
					'vue/max-attributes-per-line': 'off', // Let Prettier handle line breaks
					'vue/first-attribute-linebreak': 'off', // Let Prettier handle attribute positioning
					'vue/singleline-html-element-content-newline': 'off',
					'vue/html-self-closing': [
						'error',
						{
							html: {
								void: 'always',
								normal: 'always',
								component: 'always'
							}
						}
					],
					'vue/multi-word-component-names': 'off', // Disable multi-word name restriction
					'vue/attribute-hyphenation': ['error', 'always']
				}
			}
	  ]
	: [{ ignores: ['**/*.vue'] }];

const { hasMarkdownSupport, markdownConfigs } = await loadMarkdownSupport();
const markdownBlocks = hasMarkdownSupport ? markdownConfigs : [];

export default [
	{
		ignores: [
			'node_modules',
			'**/node_modules/**',
			'dist',
			'**/dist/**',
			'.output',
			'**/.output/**',
			'.nuxt',
			'**/.nuxt/**',
			'.nitro',
			'**/.nitro/**',
			'.netlify',
			'node_modules/.netlify',
			'coverage',
			'**/*.d.ts',
			'*.config.js',
			'public'
		]
	},
	{
		// Base rules from ESLint itself. Scoped to script files so they are not
		// applied to Markdown or JSON, which are parsed as different languages.
		files: SCRIPT_FILE_GLOBS,
		...js.configs.recommended
	},
	{
		files: SCRIPT_FILE_GLOBS,
		languageOptions: {
			globals: {
				...globals.node,
				...globals.browser,
				...globals.es2025
			}
		}
	},
	{
		files: TS_LIKE_FILE_GLOBS,
		rules: {
			// TypeScript already reports unknown identifiers, and `no-undef`
			// misfires on types and generics.
			'no-undef': 'off'
		}
	},
	{
		files: SCRIPT_FILE_GLOBS,
		plugins: {
			'@typescript-eslint': tsPlugin
		}
	},
	...vueSpecificBlocks,
	...markdownBlocks,
	{
		files: ['**/*.json'],
		languageOptions: {
			parser: jsoncParser
		},
		rules: {
			quotes: ['error', 'double'] // Enforce double quotes in JSON
		}
	},
	{
		files: [...JS_FILE_GLOBS, ...TS_FILE_GLOBS],
		languageOptions: {
			parser: tsParser,
			parserOptions: {
				ecmaVersion: 2023,
				sourceType: 'module',
				extraFileExtensions: ['.vue']
			}
		},
		plugins: {
			'import-x': pluginImportX
		},
		rules: {
			'import-x/order': [
				'error',
				{
					groups: ['builtin', 'external', 'internal', 'parent', 'sibling', 'index', 'object', 'type'],
					'newlines-between': 'always',
					alphabetize: { order: 'asc', caseInsensitive: true }
				}
			],
			// Superseded by the @typescript-eslint version on the next line.
			'no-unused-vars': 'off',
			'@typescript-eslint/no-explicit-any': ['warn'],
			'@typescript-eslint/no-unused-vars': ['warn'],
			'@typescript-eslint/no-require-imports': 'off'
		}
	},
	{
		...eslintConfigPrettier
	}
];

async function loadVueSupport() {
	try {
		const [vuePluginModule, vueConfigModule] = await Promise.all([
			import('eslint-plugin-vue'),
			import('@vue/eslint-config-typescript')
		]);

		const pluginVue = unwrapDefault(vuePluginModule);
		const { defineConfigWithVueTs, vueTsConfigs } = vueConfigModule;
		const configs = defineConfigWithVueTs(vueTsConfigs.recommended);

		return {
			hasVueSupport: Boolean(pluginVue && configs.length),
			pluginVue,
			vueTypeScriptConfigs: configs
		};
	} catch (error) {
		if (isModuleNotFoundError(error)) {
			return {
				hasVueSupport: false,
				pluginVue: null,
				vueTypeScriptConfigs: []
			};
		}

		throw error;
	}
}

async function loadMarkdownSupport() {
	try {
		const markdownModule = await import('@eslint/markdown');
		const markdownPlugin = unwrapDefault(markdownModule);
		const recommended = Array.isArray(markdownPlugin?.configs?.recommended)
			? markdownPlugin.configs.recommended
			: [];

		if (recommended.length === 0) {
			return {
				hasMarkdownSupport: false,
				markdownConfigs: []
			};
		}

		return {
			hasMarkdownSupport: true,
			markdownConfigs: [
				...recommended,
				{
					files: ['**/*.md'],
					language: 'markdown/gfm',
					rules: {
						'markdown/fenced-code-language': 'off',
						'markdown/no-missing-label-refs': 'off'
					}
				}
			]
		};
	} catch (error) {
		if (isModuleNotFoundError(error)) {
			return {
				hasMarkdownSupport: false,
				markdownConfigs: []
			};
		}

		throw error;
	}
}

function scopeVueConfigs(configs) {
	return configs.map((config) => {
		const files = config.files ?? [];
		const referencesOnlyVueFiles = files.length > 0 && files.every((pattern) => pattern.includes('.vue'));
		const hasVuePlugin = Boolean(config.plugins?.vue);

		if (hasVuePlugin || referencesOnlyVueFiles) {
			return {
				...config,
				files: VUE_FILE_GLOBS
			};
		}

		return {
			...config,
			files: TS_LIKE_FILE_GLOBS
		};
	});
}

function stripTypeScriptPlugin(config) {
	const { plugins = {}, ...rest } = config;

	if (!plugins['@typescript-eslint']) {
		return config;
	}

	const otherPlugins = { ...plugins };
	delete otherPlugins['@typescript-eslint'];
	const hasOtherPlugins = Object.keys(otherPlugins).length > 0;

	return {
		...rest,
		...(hasOtherPlugins ? { plugins: otherPlugins } : {})
	};
}

function unwrapDefault(module) {
	return module?.default ?? module;
}

function isModuleNotFoundError(error) {
	if (!error) {
		return false;
	}

	if (error.code === 'ERR_MODULE_NOT_FOUND' || error.code === 'MODULE_NOT_FOUND') {
		return true;
	}

	return typeof error.message === 'string' && error.message.includes('Cannot find module');
}
