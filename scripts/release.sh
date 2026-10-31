#!/bin/sh
# Cuts a release: sets the version, runs the pre-commit checks, commits, tags, and pushes after asking.
# The tag push starts .github/workflows/release.yml, which builds the DMGs and publishes the GitHub Release once every job passes.
#
#   scripts/release.sh 0.2.0
set -eu
cd "$(dirname "$0")/.."

version="${1:-}"
if ! echo "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "usage: scripts/release.sh X.Y.Z" >&2
  exit 2
fi
tag="v$version"

[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || { echo "Release from main." >&2; exit 1; }
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "Commit or stash your changes first." >&2; exit 1; }
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null || git ls-remote --exit-code --tags origin "$tag" >/dev/null 2>&1; then
  echo "$tag already exists." >&2
  exit 1
fi

# The root Cargo.toml's [workspace.package] version is the one source: the App, the CLI and the DMG all read it.
# package.json follows only so the two never disagree.
sed -i '' "/^\[workspace.package\]/,/^\[/ s/^version = \".*\"/version = \"$version\"/" Cargo.toml
sed -i '' "1,/\"version\":/ s/\"version\": \".*\"/\"version\": \"$version\"/" app/package.json
cargo update --workspace --quiet

echo "Running the checks…"
cargo test --workspace --quiet
cargo clippy --workspace --quiet -- -D warnings
(cd app && pnpm exec tsc --noEmit && pnpm -s check:i18n)

committed=no
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  git commit --quiet -am "Release $tag"
  committed=yes
fi
git tag -a "$tag" -m "Tsuba $tag"
echo
echo "Tagged $tag at $(git rev-parse --short HEAD)."
printf "Push main and %s to GitHub now? This starts the release build. [y/N] " "$tag"
read -r answer
case "$answer" in
  y | Y)
    git push origin main "$tag"
    echo "Pushed. Follow the build with: gh run watch \$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
    ;;
  *)
    echo "Not pushed. When ready: git push origin main $tag"
    if [ "$committed" = yes ]; then
      echo "To undo instead: git tag -d $tag && git reset --hard HEAD~1"
    else
      echo "To undo instead: git tag -d $tag"
    fi
    ;;
esac
