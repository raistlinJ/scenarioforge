#!/usr/bin/env bash
# Build the static traffic agent for every architecture a CORE node might be.
#
# Neither the workstation nor the CORE VM needs a Go toolchain: the build runs
# in a container. Binaries are static (CGO_ENABLED=0) so they run on any base
# image, including distroless and scratch, with no interpreter, no package
# manager, and no network at run time.
#
# Both architectures are always built. A Docker node can be an emulated amd64
# image on an arm64 host, so the node -- not the build host -- decides which
# binary applies.
#
# Usage:
#   traffic_agent/build.sh              # build into traffic_agent/bin
#   GO_IMAGE=golang:1.22 build.sh       # pin a different toolchain image
# The output directory is `bin`, not `dist`: `dist` is excluded by both
# .gitignore and REPO_PUSH_EXCLUDE_DIRS, so binaries placed there would be
# silently dropped from the repo push and never reach the CORE VM.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
go_image="${GO_IMAGE:-golang:1.22-alpine}"
version="${AGENT_VERSION:-1.0.0}"
out="$here/bin"

if ! command -v docker >/dev/null 2>&1; then
  echo "build.sh: docker is required (it supplies the Go toolchain)" >&2
  exit 1
fi

mkdir -p "$out"

echo "building traffic-agent $version using $go_image"
docker run --rm \
  -v "$here":/src \
  -w /src \
  "$go_image" \
  sh -c '
    set -eu
    go vet ./...
    go test ./...
    for arch in amd64 arm64; do
      CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
        go build -trimpath -ldflags "-s -w -X main.version='"$version"'" \
        -o "/src/bin/traffic-agent-linux-$arch" .
      echo "  built bin/traffic-agent-linux-$arch"
    done
  '

echo
ls -la "$out"
