#!/usr/bin/env bash
set -euo pipefail

PKG_DIR=""
DRY_RUN=false

for arg in "$@"; do
	case "$arg" in
		--)
			;;
		--ci)
			;;
		--dry-run)
			DRY_RUN=true
			;;
		-*)
			echo "Unknown option: $arg" >&2
			exit 2
			;;
		*)
			if [ -n "$PKG_DIR" ]; then
				echo "Only one package directory may be supplied." >&2
				exit 2
			fi
			PKG_DIR="$arg"
			;;
	esac
done

if [ -z "$PKG_DIR" ]; then
	PKG_DIR="$(pwd)"
fi

PKG_DIR="$(cd "$PKG_DIR" && pwd)"
NAME="$(node -p "require('$PKG_DIR/package.json').name")"
VERSION="$(node -p "require('$PKG_DIR/package.json').version")"

if [ -z "${npm_config_cache:-}" ] && [ -z "${NPM_CONFIG_CACHE:-}" ]; then
	export npm_config_cache="${TMPDIR:-/tmp}/apicore-npm-cache"
fi

PUBLISH_ARGS=(publish --access public --ignore-scripts)

if echo "$VERSION" | grep -q "-"; then
	tag_name="${VERSION#*-}"
	tag_name="${tag_name%%.*}"
	PUBLISH_ARGS+=(--tag "$tag_name")
fi

if [ "$DRY_RUN" = true ]; then
	PUBLISH_ARGS+=(--dry-run)
	echo "Dry-run publishing ${NAME}@${VERSION} from ${PKG_DIR}"
else
	echo "Publishing ${NAME}@${VERSION} from ${PKG_DIR}"
fi

(
	cd "$PKG_DIR"
	unset npm_config_npm_globalconfig
	unset npm_config_verify_deps_before_run
	unset npm_config__jsr_registry
	unset npm_config_only_built_dependencies
	unset npm_config_global_bin_dir
	npm "${PUBLISH_ARGS[@]}"
)
