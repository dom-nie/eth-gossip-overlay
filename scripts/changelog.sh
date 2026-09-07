#!/usr/bin/env bash
# Everything that knows the shape of CHANGELOG.md, in one place.
#
#   scripts/changelog.sh check [<base-ref>] [<head-ref>]
#   scripts/changelog.sh section <version|Unreleased>
#   scripts/changelog.sh major <version|Unreleased>
#   scripts/changelog.sh bits <version|Unreleased>
#
# check    fails when the diff touches a crate's src/ and leaves CHANGELOG.md alone. A change an
#          operator can see is a change they can read about; the escape hatch for the ones they
#          cannot is the skip-changelog label, which CI passes in LABELS.
# section  prints a section's body, which is what a release's notes are made of.
# major    prints the protocol major that section's `Protocol:` line names, and bits the feature
#          bit positions it says were added, so the release workflow can hold the published
#          binary to what the notes claim (D29).
#
# LABELS   space-separated pull request labels, for check
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
changelog=$root/CHANGELOG.md

usage() {
  sed -n '4,7p' "$0" >&2
  exit 2
}

# The lines under `## [<version>]`, with the blank lines around them dropped.
section() {
  awk -v want="$1" '
    /^## \[/ { inside = (substr($0, 5, index($0, "]") - 5) == want); next }
    inside { line[++n] = $0; if (NF) { if (!first) first = n; last = n } }
    END { for (i = first; i <= last; i++) print line[i] }
  ' "$changelog"
}

# `Protocol: major unchanged (1); features added: none` or `Protocol: major 1 → 2; features
# added: STRIPING (bit 1)`. The major a release runs at is the number on the right either way.
major() {
  local line major
  line=$(section "$1" | grep -m1 '^Protocol: major ' || true)
  if [ -z "$line" ]; then
    echo "no \`Protocol:\` line in the [$1] section of CHANGELOG.md" >&2
    return 1
  fi
  case $line in
    "Protocol: major unchanged ("*)
      major=${line#Protocol: major unchanged (}
      major=${major%%)*}
      ;;
    "Protocol: major "*" → "*)
      major=${line#* → }
      major=${major%%;*}
      ;;
    *)
      echo "cannot read a major out of: $line" >&2
      return 1
      ;;
  esac
  case $major in
    '' | *[!0-9]*)
      echo "cannot read a major out of: $line" >&2
      return 1
      ;;
  esac
  echo "$major"
}

# The bit positions of `features added: NAME (bit N), ...`, one per line and nothing for `none`.
bits() {
  local line features
  line=$(section "$1" | grep -m1 '^Protocol: major ') || {
    echo "no \`Protocol:\` line in the [$1] section of CHANGELOG.md" >&2
    return 1
  }
  features=${line#*; features added: }
  if [ "$features" = none ]; then
    return 0
  fi
  printf '%s\n' "$features" | tr ',' '\n' | sed -n 's/.*(bit \([0-9]*\)).*/\1/p'
}

check() {
  local base=${1:-origin/main} head=${2:-HEAD} changed code
  case " ${LABELS:-} " in
    *" skip-changelog "*)
      echo "skip-changelog is on the pull request, not asking for an entry"
      return 0
      ;;
  esac

  changed=$(git -C "$root" diff --name-only "$base...$head" --)
  code=$(printf '%s\n' "$changed" | grep -E '^crates/[^/]+/src/' || true)
  if [ -z "$code" ]; then
    echo "no crate source in $base...$head, nothing to note"
    return 0
  fi
  if printf '%s\n' "$changed" | grep -qx 'CHANGELOG.md'; then
    echo "CHANGELOG.md is in $base...$head"
    return 0
  fi

  cat >&2 <<MESSAGE
This change touches crate sources and leaves CHANGELOG.md alone:

$code

Add a line to the Unreleased section saying what an operator gets out of it, or put the
skip-changelog label on the pull request when there is nothing for one to read.
MESSAGE
  return 1
}

command=${1-}
[ -n "$command" ] || usage
shift
case $command in
  check) check "$@" ;;
  section) section "${1:?which section}" ;;
  major) major "${1:?which section}" ;;
  bits) bits "${1:?which section}" ;;
  *) usage ;;
esac
