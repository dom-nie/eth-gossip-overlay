#!/usr/bin/env bash
# The release tarball for one target, and the check that it holds what a release promises.
#
#   scripts/package.sh <version> <target-triple> [<bin-dir>] [<out-dir>]
#
# Puts the two binaries, the licence and the deploy/ examples under one directory named after the
# version and the target, tars it, and then lists the tarball back and compares it with what
# should be in there. The release profile already strips, so nothing is stripped again here.
#
# bin-dir defaults to target/release and out-dir to dist/.
set -euo pipefail

version=${1:?usage: package.sh <version> <target-triple> [bin-dir] [out-dir]}
triple=${2:?usage: package.sh <version> <target-triple> [bin-dir] [out-dir]}
root=$(cd "$(dirname "$0")/.." && pwd)
bindir=${3:-$root/target/release}
outdir=${4:-$root/dist}

name=eth-gossip-overlay-$version-$triple
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/$name" "$outdir"
install -m 755 "$bindir/eth-gossip-overlay" "$bindir/eth-gossip-overlayctl" "$stage/$name/"
install -m 644 "$root/LICENSE" "$stage/$name/"
cp -R "$root/deploy" "$stage/$name/deploy"

tarball=$outdir/$name.tar.gz
tar -czf "$tarball" -C "$stage" "$name"

# tarball_contains_expected_files: the two binaries an operator installs, the licence they are
# under, and every deployment example the repository ships, with nothing else along for the ride.
expected=$(
  {
    printf '%s\n' eth-gossip-overlay eth-gossip-overlayctl LICENSE
    (cd "$root" && find deploy -type f)
  } | sed "s|^|$name/|" | sort
)
actual=$(tar -tzf "$tarball" | grep -v '/$' | sort)

if [ "$expected" != "$actual" ]; then
  echo "FAIL tarball_contains_expected_files" >&2
  diff <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
  exit 1
fi

printf 'ok   tarball_contains_expected_files (%s, %s bytes)\n' "$tarball" "$(wc -c < "$tarball" | tr -d ' ')"
printf '%s\n' "$actual"
