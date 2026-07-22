#!/bin/sh
set -eu

version=${1:?usage: check-release-version.sh VERSION}
manifest_version=$(sed -n 's/^version = "\([0-9][0-9.]*\)"/\1/p' Cargo.toml | head -1)
test "$version" = "$manifest_version" || {
  printf 'requested %s but Cargo.toml contains %s\n' "$version" "$manifest_version" >&2
  exit 1
}
grep -Fqx "## $version - Unreleased" CHANGELOG.md \
  || grep -Eq "^## ${version} - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md \
  || {
    printf 'CHANGELOG.md has no entry for %s\n' "$version" >&2
    exit 1
  }
printf 'self-hosted release version contract: %s\n' "$version"
