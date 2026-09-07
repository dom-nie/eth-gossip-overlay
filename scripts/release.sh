#!/usr/bin/env bash
# The one command that cuts a release.
#
#   scripts/release.sh <version> [--dry-run]
#
# Checks that the Unreleased section says what the release means for a mixed-version fleet, bumps
# the workspace version and the image label, moves the section under the new version with today's
# date, leaves an empty Unreleased behind, commits and tags. Pushing the tag is what starts the
# release workflow, and that stays a separate deliberate step.
#
# --dry-run prints every change it would make and writes nothing.
set -euo pipefail

version=${1:?usage: release.sh <version> [--dry-run]}
dry_run=0
if [ "${2-}" = "--dry-run" ]; then
  dry_run=1
elif [ -n "${2-}" ]; then
  echo "release.sh: unknown argument ${2}" >&2
  exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

say() { printf '%s\n' "$*"; }
refuse() {
  printf 'release.sh: %s\n' "$*" >&2
  exit 1
}

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || refuse "$version is not a semantic version"
if git rev-parse -q --verify "refs/tags/v$version" > /dev/null; then
  refuse "v$version is already tagged"
fi

if [ "$dry_run" = 0 ] && [ -n "$(git status --porcelain)" ]; then
  refuse "the working tree is not clean"
fi

# The release notes claim a protocol major and the binary prints one; they have to be the same
# number or an operator reading the notes plans the wrong rollout (D29).
constant=$(sed -n 's/^pub const PROTOCOL_MAJOR: u8 = \([0-9]*\);.*/\1/p' crates/overlay-core/src/protocol.rs)
[ -n "$constant" ] || refuse "cannot read PROTOCOL_MAJOR out of crates/overlay-core/src/protocol.rs"
claimed=$(scripts/changelog.sh major Unreleased) || refuse "the Unreleased section is not releasable"
[ "$claimed" = "$constant" ] || refuse "Unreleased claims protocol major $claimed, the build is $constant"

today=$(date -u +%F)
staged=$(mktemp -d)
trap 'rm -rf "$staged"' EXIT

awk -v v="$version" -v d="$today" -v m="$constant" '
  $0 == "## [Unreleased]" && !moved {
    print "## [Unreleased]"
    print ""
    print "Protocol: major unchanged (" m "); features added: none"
    print ""
    print "## [" v "] - " d
    moved = 1
    next
  }
  { print }
' CHANGELOG.md > "$staged/CHANGELOG.md"

sed "s/^version = \".*\"$/version = \"$version\"/" Cargo.toml > "$staged/Cargo.toml"
sed "s|org.opencontainers.image.version=\".*\"|org.opencontainers.image.version=\"$version\"|" Dockerfile > "$staged/Dockerfile"

files=(CHANGELOG.md Cargo.toml Dockerfile)
if [ "$dry_run" = 1 ]; then
  say "release.sh --dry-run: v$version on $today, protocol major $constant"
  say ""
  for file in "${files[@]}"; do
    diff -u "$file" "$staged/$file" || true
  done
  say "would then: cargo update --workspace, commit ${files[*]} and Cargo.lock, tag v$version"
  say "the working tree has to be clean for the real run; nothing was written"
  exit 0
fi

for file in "${files[@]}"; do
  cp "$staged/$file" "$file"
done
cargo update --workspace --offline > /dev/null

git add "${files[@]}" Cargo.lock
git commit -m "release v$version"
git tag -a "v$version" -m "v$version"

say "tagged v$version. Push it when you mean it: git push origin main v$version"
