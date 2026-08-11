#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

set +e
bash "$SCRIPT_DIR/release-check.sh" --strict-ready
status=$?
set -e

if [ "$status" -eq 3 ]; then
	exit 0
fi
if [ "$status" -ne 0 ]; then
	exit "$status"
fi

NAME="$(node -p "require('$ROOT/package.json').name")"
VERSION="$(node -p "require('$ROOT/package.json').version")"

case "$NAME" in
	"@technomoron/apicore-server")
		TAG_PREFIX="server-v"
		;;
	"@technomoron/apicore-client")
		TAG_PREFIX="client-v"
		;;
	*)
		echo "Unsupported package for release tagging: ${NAME}" >&2
		exit 1
		;;
esac

TAG_NAME="${TAG_PREFIX}${VERSION}"

echo "Creating release tag ${TAG_NAME} for ${NAME}@${VERSION}"

git -C "$ROOT" tag -a "$TAG_NAME" -m "Release ${NAME} ${VERSION}"
echo "Created ${TAG_NAME}. Push tags with: git push --tags"
