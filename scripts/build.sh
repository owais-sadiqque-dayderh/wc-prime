#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
VERSION=${VERSION:-dev}
mkdir -p dist
for target in linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 android/arm64; do
    target_os=${target%/*}
    target_arch=${target#*/}
    output="dist/wcprime-${target_os}-${target_arch}"
    flags="-s -w -X main.version=$VERSION"
    if [[ "$target_os" == windows ]]; then
        output+='.exe'
        flags+=' -H windowsgui'
    fi
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" GOARM=7 \
        go build -trimpath -ldflags "$flags" -o "$output" ./cmd/wcprime
    printf '%s: %s bytes\n' "$output" "$(wc -c < "$output" | tr -d ' ')"
done
