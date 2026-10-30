#!/usr/bin/env bash
# Build the sensiflow image from a clean `git archive` of HEAD.
#
# `docker build .` ships the working tree, so untracked or gitignored files under
# src/ (a stray module, local scratch) could end up in the wheel. Building from
# the archive makes the build context exactly the committed tree, whatever the
# state of the working copy. Uncommitted changes are NOT included: commit first.
#
# Usage: scripts/docker-build.sh [extra docker build args]
# Follow-up once repository CI exists: assert the built wheel's file list in CI.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

version="$(sed -n 's/^version = "\(.*\)"$/\1/p' pyproject.toml | head -n 1)"
[ -n "${version}" ] || { echo "cannot read the version from pyproject.toml" >&2; exit 1; }

if ! git diff --quiet HEAD --; then
    echo "warning: uncommitted changes are not part of the image (building HEAD)" >&2
fi

git archive --format=tar HEAD | docker build -t "sensiflow:${version}" "$@" -
