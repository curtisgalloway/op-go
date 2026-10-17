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
mkdir -p bin
build_dir="bin/.signed-build.$$"
umask 077
mkdir "$build_dir"
trap 'rm -f "$build_dir/op-go" "$build_dir/launch.test" "$build_dir/signature.txt"; rmdir "$build_dir"' EXIT

CGO_ENABLED=1 go build -o "$build_dir/op-go" ./cmd/op-go
CGO_ENABLED=1 go test -c -o "$build_dir/launch.test" ./internal/launch
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
