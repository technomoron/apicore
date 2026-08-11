#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

PACKAGE_DIRS=(
	"$ROOT/packages/server"
	"$ROOT/packages/client"
)

checked_count=0

for pkg_dir in "${PACKAGE_DIRS[@]}"; do
	if [ ! -f "$pkg_dir/package.json" ]; then
		continue
	fi

	if ! node -e "const p=require(process.argv[1]); process.exit(p.scripts && p.scripts['release:check'] ? 0 : 1)" "$pkg_dir/package.json"; then
		echo "Skip $(basename "$pkg_dir"): no release:check script."
		continue
	fi

	echo "Running release readiness for $(basename "$pkg_dir")"
	if pnpm --dir "$pkg_dir" run release:check; then
		checked_count=$((checked_count + 1))
	else
		echo "Release readiness failed for $pkg_dir" >&2
		exit 1
	fi
done

if [ "$checked_count" -eq 0 ]; then
	echo "No package release:check scripts executed."
else
	echo "Release readiness flow completed."
fi
