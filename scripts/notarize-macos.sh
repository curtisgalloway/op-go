#!/bin/bash
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
binary="${1:?Usage: notarize-macos.sh binary version output-directory}"
version="${2:?Specify version}"
output="${3:?Specify output directory}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
identity="${MACOS_SIGNING_IDENTITY:-Developer ID Application}"
: "${MACOS_NOTARY_KEY_FILE:?Set the path to the project notary key}"
: "${MACOS_NOTARY_KEY_ID:?Set the project notary key ID}"
: "${MACOS_NOTARY_ISSUER_ID:?Set the notary issuer ID}"
mkdir -p "$output"
stage="$output/.notary-stage.$$"
mkdir "$stage"
cleanup() {
    if [[ -d "$stage/mounted" ]]; then
        hdiutil detach "$stage/mounted" >/dev/null 2>&1 || true
        rmdir "$stage/mounted" || true
    fi
    rm -f "$stage/op-go" "$stage/installed-op-go" "$stage/README.md" "$stage/LICENSE"
    rmdir "$stage"
}
trap cleanup EXIT
ditto "$binary" "$stage/op-go"
cp README.md LICENSE "$stage/"
image="$output/op-go-v$version-darwin-universal.dmg"
hdiutil create -quiet -volname op-go -srcfolder "$stage" -format UDZO "$image"
codesign --sign "$identity" --timestamp "$image"
codesign --verify --strict "$image"
xcrun notarytool submit "$image" --key "$MACOS_NOTARY_KEY_FILE" \
    --key-id "$MACOS_NOTARY_KEY_ID" --issuer "$MACOS_NOTARY_ISSUER_ID" \
    --wait --timeout 20m --output-format json > "$output/notary-result.json"
python3 - "$output/notary-result.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
if result.get("status") != "Accepted":
    sys.exit("Notarization was not accepted; refusing to package or publish")
print("Notarization accepted")
PY
xcrun stapler staple "$image"
xcrun stapler validate "$image"
spctl --assess --type open --context context:primary-signature "$image"
mkdir "$stage/mounted"
hdiutil attach -readonly -nobrowse -mountpoint "$stage/mounted" "$image"
ditto "$stage/mounted/op-go" "$stage/installed-op-go"
cmp "$binary" "$stage/installed-op-go"
codesign --verify --strict "$stage/installed-op-go"
python3 scripts/smoke-release.py "$stage/installed-op-go" "$version"
hdiutil detach "$stage/mounted"
rmdir "$stage/mounted"
