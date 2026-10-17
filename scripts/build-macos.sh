#!/bin/bash
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if [[ "${OSTYPE:-}" != darwin* ]]; then
    printf '%s\n' 'This build script requires macOS.' >&2
    exit 3
fi
if [[ ! -f go.mod || ! -d cmd/op-go ]]; then
    printf '%s\n' 'Run this script from the repository root.' >&2
    exit 2
fi

identity="${MACOS_SIGNING_IDENTITY:-Developer ID Application}"
version="${OP_GO_VERSION:-0.1.0-dev}"
commit="${OP_GO_COMMIT:-unknown}"
date="${OP_GO_DATE:-unknown}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-dev)?$ ]] ||
   [[ ! "$commit" =~ ^([0-9a-f]{40}|unknown)$ ]] ||
   [[ ! "$date" =~ ^([0-9TZ:-]+|unknown)$ ]]; then
    printf '%s\n' 'Invalid version, commit, or build date.' >&2
    exit 2
fi
ldflags="-X github.com/curtisgalloway/op-go/internal/cli.Version=$version -X github.com/curtisgalloway/op-go/internal/cli.Commit=$commit -X github.com/curtisgalloway/op-go/internal/cli.Date=$date"
mkdir -p bin
build_dir="bin/.signed-build.$$"
umask 077
mkdir "$build_dir"
trap 'rm -f "$build_dir/op-go" "$build_dir/op-go-arm64" "$build_dir/op-go-amd64" "$build_dir/launch.test" "$build_dir/signature.txt"; rmdir "$build_dir"' EXIT

if [[ "${MACOS_UNIVERSAL:-0}" == 1 ]]; then
    for arch in arm64 amd64; do
        CGO_ENABLED=1 GOARCH="$arch" go build -trimpath -ldflags "$ldflags" -o "$build_dir/op-go-$arch" ./cmd/op-go
    done
    lipo -create "$build_dir/op-go-arm64" "$build_dir/op-go-amd64" -output "$build_dir/op-go"
    lipo "$build_dir/op-go" -verify_arch arm64
    lipo "$build_dir/op-go" -verify_arch x86_64
else
    CGO_ENABLED=1 go build -trimpath -ldflags "$ldflags" -o "$build_dir/op-go" ./cmd/op-go
fi
CGO_ENABLED=1 go test -trimpath -c -o "$build_dir/launch.test" ./internal/launch
for executable in op-go launch.test; do
    codesign --force --sign "$identity" \
        --identifier "com.github.curtisgalloway.$executable" \
        --options runtime --timestamp \
        --entitlements scripts/macos-entitlements.plist "$build_dir/$executable"
    codesign --verify --strict "$build_dir/$executable"
    codesign -dvvv "$build_dir/$executable" 2> "$build_dir/signature.txt"
    grep -q '^Authority=Developer ID Application:' "$build_dir/signature.txt"
    grep -q '^Timestamp=' "$build_dir/signature.txt"
    grep -Eq '^TeamIdentifier=.+$' "$build_dir/signature.txt"
    grep -q 'flags=.*runtime' "$build_dir/signature.txt"
done
env -u OP_SERVICE_ACCOUNT_TOKEN -u EXTISM_ENABLE_WASI_OUTPUT \
    "$build_dir/launch.test" -test.run '^TestSDKReferenceValidationOffline$'
"$build_dir/op-go" --version
chmod 755 "$build_dir/op-go"
mv "$build_dir/op-go" bin/op-go
printf '%s\n' 'Built and verified signed bin/op-go (not notarized).'
