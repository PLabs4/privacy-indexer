#!/usr/bin/env bash
# Resolve an existing deployment tag to an exact commit and deployment channel.
# All callers check out source_commit for both tests and image builds.
set -euo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}

deployment_tag="${DEPLOYMENT_TAG:-}"
[[ "$deployment_tag" =~ ^stack-(main|develop)-[0-9A-Za-z][0-9A-Za-z._-]*$ ]] ||
  fail "Expected a stack-main-* or stack-develop-* deployment tag"
source_branch="${BASH_REMATCH[1]}"

[[ -z "${EXPECTED_SOURCE_BRANCH:-}" || "$EXPECTED_SOURCE_BRANCH" == "$source_branch" ]] ||
  fail "Deployment tag does not match the requested source branch"

for expected in "${EXPECTED_SOURCE_COMMIT:-}" "${EXPECTED_EVENT_COMMIT:-}"; do
  [[ -z "$expected" || "$expected" =~ ^[0-9a-f]{40}$ ]] ||
    fail "Expected a full source commit SHA"
done

# Explicit refspecs avoid ambiguous branch/tag names. Refuse to overwrite a
# conflicting local tag; deployment tags must be immutable.
git fetch --no-tags origin \
  "+refs/heads/$source_branch:refs/remotes/origin/$source_branch" \
  "refs/tags/$deployment_tag:refs/tags/$deployment_tag"

# Peel annotated tags as well as lightweight tags to the source commit.
source_commit="$(git rev-parse --verify "refs/tags/$deployment_tag^{commit}")"
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || fail "Deployment tag must point to a commit"

if [[ -n "${EXPECTED_SOURCE_COMMIT:-}" ]]; then
  [[ "$source_commit" == "$EXPECTED_SOURCE_COMMIT" ]] ||
    fail "Deployment tag does not point to the reviewed source commit"
fi
if [[ -n "${EXPECTED_EVENT_COMMIT:-}" ]]; then
  event_commit="$(git rev-parse --verify "$EXPECTED_EVENT_COMMIT^{commit}")"
  [[ "$source_commit" == "$event_commit" ]] ||
    fail "Deployment tag no longer points to the commit that triggered this run"
fi

git merge-base --is-ancestor "$source_commit" "refs/remotes/origin/$source_branch" ||
  fail "Deployment tag commit is not on the selected deployment branch"

printf 'source_branch=%s\nsource_commit=%s\ndeployment_tag=%s\n' \
  "$source_branch" "$source_commit" "$deployment_tag" >> "$GITHUB_OUTPUT"
