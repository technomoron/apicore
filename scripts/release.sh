#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

PACKAGE_DIRS=(
	"$ROOT/packages/server"
	"$ROOT/packages/client"
)

released_count=0

for pkg_dir in "${PACKAGE_DIRS[@]}"; do
	if [ ! -f "$pkg_dir/package.json" ]; then
		continue
	fi

	if ! node -e "const p=require(process.argv[1]); process.exit(p.scripts && p.scripts.release ? 0 : 1)" "$pkg_dir/package.json"; then
		echo "Skip $(basename "$pkg_dir"): no release script."
		continue
	fi

	echo "Running release for $(basename "$pkg_dir")"
	if pnpm --dir "$pkg_dir" run release; then
		released_count=$((released_count + 1))
	else
		echo "Release failed for $pkg_dir" >&2
		exit 1
	fi
done

if [ "$released_count" -eq 0 ]; then
	echo "No package release scripts executed."
else
	echo "Release flow completed. Push tags with: git push --tags"
fi
