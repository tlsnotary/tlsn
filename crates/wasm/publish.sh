#!/bin/sh

# Publish a tagged tlsn-wasm build from GitHub Actions to npm.
#
# Usage:
#   ./publish.sh <tag> [npm-dist-tag]
#
# Example:
#   ./publish.sh v0.1.0-alpha.16
#   ./publish.sh v0.1.0-alpha.16 alpha
#
# Requires: gh (authenticated), npm (logged in as a maintainer of `tlsn-wasm`).

set -e

TAG="${1:-}"
NPM_TAG="${2:-latest}"

if [ -z "$TAG" ]; then
    echo "Usage: $0 <tag> [npm-dist-tag]"
    echo "Example: $0 v0.1.0-alpha.16"
    exit 1
fi

REPO="tlsnotary/tlsn"
ARTIFACT_NAME="${TAG}-tlsn-wasm-pkg"

for cmd in gh npm; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: $cmd not found in PATH."
        exit 1
    fi
done

if ! npm whoami >/dev/null 2>&1; then
    echo "Error: not logged in to npm. Run 'npm login' first."
    exit 1
fi

WORK_DIR="$(mktemp -d -t tlsn-wasm-publish.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT
echo "Working in $WORK_DIR"

echo "Looking for successful ci.yml run for $TAG..."
RUN_ID=$(gh run list \
    --repo "$REPO" \
    --workflow ci.yml \
    --branch "$TAG" \
    --status success \
    --limit 1 \
    --json databaseId \
    --jq '.[0].databaseId')

if [ -z "$RUN_ID" ] || [ "$RUN_ID" = "null" ]; then
    echo "Error: no successful ci.yml run found for tag $TAG."
    echo "Check: gh run list --repo $REPO --workflow ci.yml --branch $TAG"
    exit 1
fi
echo "Found CI run: $RUN_ID"

echo "Downloading artifact $ARTIFACT_NAME..."
gh run download "$RUN_ID" \
    --repo "$REPO" \
    --name "$ARTIFACT_NAME" \
    --dir "$WORK_DIR/pkg"

echo "Tarball preview:"
(cd "$WORK_DIR/pkg" && npm publish --dry-run --tag "$NPM_TAG")

printf "Publish %s to npm with dist-tag '%s'? [y/N] " "$ARTIFACT_NAME" "$NPM_TAG"
read -r REPLY
case "$REPLY" in
    y|Y|yes|YES) ;;
    *) echo "Aborted."; exit 1 ;;
esac

cd "$WORK_DIR/pkg"
npm publish --tag "$NPM_TAG"

echo "Published $ARTIFACT_NAME to npm under tag '$NPM_TAG'."
