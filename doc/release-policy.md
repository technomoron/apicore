# Release Policy

This repository ships workspace packages from a shared git repository. The
root release helpers are:

- `pnpm run release:check`
- `pnpm run release`

Both commands dispatch to the package-level scripts in:

- `packages/server`
- `packages/client`

`pnpm run release` only creates local package tags. It does not publish to npm.

GitHub Actions runs CI only on commits pushed to `main`. Release
automation publishes only from package-specific tag pushes whose target commit
is already reachable from `origin/main`:

- `server-v<version>`
- `client-v<version>`

Manual workflow dispatch is not part of the release path. npm publish and
GitHub release creation only happen on package tag pushes that reference
commits already on `origin/main`.

## Required Sequence Before Each Release

1. Inspect the intended scope with `git status -sb` and `git diff --stat`.
2. Confirm the release only includes intended files. If the worktree is mixed,
   stage explicit paths instead of `git add -A`.
3. Update each package version that is being released.
4. Finalize the matching `CHANGES.md` entry for each released package using the
   exact heading format `v<version> (YYYY-MM-DD)`.
5. Commit the release candidate with a terse release-focused message.
6. Push `main` so local `HEAD` matches `origin/main`.
7. Run `pnpm run release:check` from the repository root.
8. If the branch is ready to release, run `pnpm run release` to create local
   package tags only.
9. Push package tags with `git push --tags`.
10. Let the GitHub `Release` workflow publish to npm and create the GitHub
    release from the pushed tags.

## Hard Gates Enforced By `release:check`

The root and package-level `release-check.sh` scripts fail or skip on the
following conditions.

- Clean worktree is required.
  Fix: commit or stash all pending changes before release.
- An upstream branch is required.
  Fix: set upstream with `git push -u origin $(git branch --show-current)` if
  needed.
- The branch must be exactly in sync with upstream.
  Fix: pull or push until ahead and behind are both `0`.
- `git fetch` must succeed.
  Fix: restore remote access, network access, and git authentication before
  retrying.
- Private packages are skipped.
  Note: the root package is private; the root helper only dispatches to the
  releasable workspace packages.
- Tag `server-v<version>` or `client-v<version>` must not already exist for the
  package being released.
  Fix: stop if that package version is already released, or bump the package
  version.
- The current package version must be newer than the latest matching package
  tag.
  Fix: bump the semver or prerelease identifier.
- There must be committed changes since the latest matching package tag. The
  first release has no previous tag and uses the initial commit.
  Fix: ensure the release commit contains real changes.
- `CHANGES.md` must contain `v<version> (YYYY-MM-DD)`.
  Fix: replace the unreleased heading with the release heading before
  tagging.

## Checks Still Needed Before Tagging

`release:check` runs the git, version, and changelog release gates. It does not
run lint, tests, or builds. Those still matter before release because local
`pnpm run release` only creates tags.

- Recommended preflight from repo root:
  `pnpm -r lint && pnpm -r test && pnpm -r build`
- The GitHub `Release` workflow rebuilds, packs, and publishes the tagged
  package after the tag push.

Fix any lint, test, type, or build failures before invoking `pnpm run release`.

## Important Repo Note

Each releasable package has its own git tag namespace:

- `server-v<version>`
- `client-v<version>`

Keep the package release scripts and the GitHub workflow aligned to those tag
prefixes. If the tag format changes, update both together before the next
publish.
