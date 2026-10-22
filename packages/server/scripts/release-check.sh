#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-normal}"

skip() {
	local message="$1"
	echo "Skip ${message}"
	if [ "$MODE" = "--strict-ready" ]; then
		exit 3
	fi
	exit 0
}

if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
	echo "Working tree is not clean. Commit or stash changes before release." >&2
	exit 1
fi

BRANCH="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)"
UPSTREAM="$(git -C "$ROOT" rev-parse --abbrev-ref --symbolic-full-name @{u} 2>/dev/null || true)"
if [ -z "$UPSTREAM" ]; then
	echo "No upstream configured for ${BRANCH}. Set upstream before release." >&2
	exit 1
fi

if ! git -C "$ROOT" fetch --quiet; then
	echo "Failed to fetch remote updates. Check network/remote access." >&2
	exit 1
fi

set -- $(git -C "$ROOT" rev-list --left-right --count "${UPSTREAM}...HEAD")
BEHIND="$1"
AHEAD="$2"
if [ "$BEHIND" -ne 0 ] || [ "$AHEAD" -ne 0 ]; then
	echo "Branch ${BRANCH} is not in sync with ${UPSTREAM} (behind ${BEHIND}, ahead ${AHEAD})." >&2
	echo "Pull/push until branch matches upstream before release." >&2
	exit 1
fi

NAME="$(node -p "require('$ROOT/package.json').name")"
VERSION="$(node -p "require('$ROOT/package.json').version")"
PRIVATE="$(node -p "Boolean(require('$ROOT/package.json').private)")"

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

if [ "$PRIVATE" = "true" ]; then
	skip "${NAME}: private package."
fi

if git -C "$ROOT" rev-parse -q --verify "refs/tags/${TAG_NAME}" >/dev/null; then
	skip "${NAME}: tag ${TAG_NAME} already exists."
fi

LAST_TAG="$(git -C "$ROOT" tag -l "${TAG_PREFIX}*" --sort=-v:refname | head -n1 || true)"
LAST_VERSION=""
if [ -n "$LAST_TAG" ]; then
	LAST_VERSION="${LAST_TAG#${TAG_PREFIX}}"
fi

if [ -n "$LAST_VERSION" ]; then
	if ! node - "$VERSION" "$LAST_VERSION" <<'NODE'
const [current, previous] = process.argv.slice(2);
const normalize = (v) => v.replace(/^v/, '');
const parse = (v) => {
	const [main, pre] = normalize(v).split('-');
	const parts = main.split('.').map((n) => parseInt(n, 10) || 0);
	return { parts, pre: pre ? pre.split('.') : [] };
};
const compare = (a, b) => {
	for (let i = 0; i < 3; i += 1) {
		const ai = a.parts[i] || 0;
		const bi = b.parts[i] || 0;
		if (ai > bi) return 1;
		if (ai < bi) return -1;
	}
	if (!a.pre.length && !b.pre.length) return 0;
	if (!a.pre.length) return 1;
	if (!b.pre.length) return -1;
	const len = Math.max(a.pre.length, b.pre.length);
	for (let i = 0; i < len; i += 1) {
		const ai = a.pre[i];
		const bi = b.pre[i];
		if (ai === undefined) return -1;
		if (bi === undefined) return 1;
		const an = Number(ai);
		const bn = Number(bi);
		const aNum = String(an) === ai;
		const bNum = String(bn) === bi;
		if (aNum && bNum) {
			if (an > bn) return 1;
			if (an < bn) return -1;
			continue;
		}
		if (aNum && !bNum) return -1;
		if (!aNum && bNum) return 1;
		if (ai > bi) return 1;
		if (ai < bi) return -1;
	}
	return 0;
};
const result = compare(parse(current), parse(previous));
process.exit(result > 0 ? 0 : 1);
NODE
	then
		skip "${NAME}: version ${VERSION} is not newer than ${LAST_VERSION}."
	fi
fi

if [ -n "$LAST_TAG" ] && ! git -C "$ROOT" diff --name-only "$LAST_TAG"..HEAD | grep -q .; then
	skip "${NAME}: no changes since ${LAST_TAG}."
fi

CHANGES_FILE="$ROOT/CHANGES.md"
if [ ! -f "$CHANGES_FILE" ]; then
	echo "Missing CHANGES.md file for ${NAME}" >&2
	exit 1
fi

if ! awk -v v="$VERSION" '
	/^(v[0-9]|Version [0-9])/ {
		line = $0
		sub(/^(v|Version )/, "", line)
		ver = line
		sub(/[[:space:]]+\(.*/, "", ver)
		if (ver == v) {
			found = 1
		}
	}
	END { exit(found ? 0 : 1) }
' "$CHANGES_FILE"; then
	echo "${CHANGES_FILE} is missing 'Version ${VERSION} (<YYYY-MM-DD>)' or its legacy v-prefixed heading." >&2
	echo "Add the version section before release." >&2
	exit 1
fi

echo "Ready ${NAME}@${VERSION} (${TAG_NAME})"
