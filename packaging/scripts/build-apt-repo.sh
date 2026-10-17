#!/bin/bash
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Curtis Galloway
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Assemble the signed apt repository that docs.yml publishes to GitHub Pages
# under /apt/. Stateless by design: point it at a directory of .debs (the
# workflow downloads them from recent GitHub Releases) and it emits a complete
# pooled repo — pool/, per-arch Packages indexes, a GPG-signed
# Release/InRelease, and the public key as op-go.asc — into the output dir.
# Nothing is kept between runs, so the live repo always mirrors the releases.
#
# The signing key must already be imported into the calling GNUPGHOME and must
# have no passphrase (CI runs non-interactively).
#
# Usage: build-apt-repo.sh <debs-dir> <out-dir> <signing-key-fingerprint>

set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <debs-dir> <out-dir> <signing-key-fingerprint>" >&2
  exit 2
fi

DEBS_DIR="$1"
OUT="$2"
KEY="$3"

SUITE=stable
COMPONENT=main
ARCHES="amd64 arm64"
BASE_URL="https://curtisgalloway.github.io/op-go/apt"

command -v dpkg-scanpackages >/dev/null 2>&1 || {
  echo "error: dpkg-scanpackages not found (apt-get install dpkg-dev)" >&2
  exit 1
}
command -v apt-ftparchive >/dev/null 2>&1 || {
  echo "error: apt-ftparchive not found (apt-get install apt-utils)" >&2
  exit 1
}
ls "$DEBS_DIR"/*.deb >/dev/null 2>&1 || {
  echo "error: no .deb files in $DEBS_DIR" >&2
  exit 1
}

seen_amd64=false
seen_arm64=false
for deb in "$DEBS_DIR"/*.deb; do
  if [ "$(dpkg-deb --field "$deb" Package)" != op-go ]; then
    echo "error: input includes a package other than op-go" >&2
    exit 1
  fi
  case "$(dpkg-deb --field "$deb" Architecture)" in
    amd64) seen_amd64=true ;;
    arm64) seen_arm64=true ;;
    *) echo "error: unsupported package architecture" >&2; exit 1 ;;
  esac
done
if ! "$seen_amd64" || ! "$seen_arm64"; then
  echo "error: repository requires both amd64 and arm64 packages" >&2
  exit 1
fi

# The fingerprint index.html shows is read from the key that signs, so the
# page cannot drift from the key docs.yml actually imported.
FPR="$(gpg --batch --with-colons --fingerprint "$KEY" \
  | awk -F: '/^fpr:/ {print $10; exit}')"
[ -n "$FPR" ] || {
  echo "error: no fingerprint for signing key $KEY (not imported?)" >&2
  exit 1
}

# apt refuses the repo once this passes, which bounds how long a stale or
# replayed index can be served. 30 days; docs.yml rebuilds weekly on a
# schedule as well as on every release, so a live repo never reaches it.
# apt-ftparchive derives the Valid-Until field from ValidTime (seconds after
# Date); it silently ignores a Valid-Until value given directly (verified
# against apt 2.8: the field was missing from the published Release).
VALID_SECONDS=$((30 * 24 * 3600))

# Never merge into an old index tree: stale Release files can hash themselves.
if [ -d "$OUT" ] && [ -n "$(find "$OUT" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  echo "error: output directory must be empty" >&2
  exit 1
fi

POOL="pool/$COMPONENT/o/op-go"
mkdir -p "$OUT/$POOL"
cp "$DEBS_DIR"/*.deb "$OUT/$POOL/"

cd "$OUT"

# --multiversion keeps every release in the index (the pool holds the last few
# releases so clients can pin or roll back); without it dpkg-scanpackages
# silently drops all but the newest.
for arch in $ARCHES; do
  bindir="dists/$SUITE/$COMPONENT/binary-$arch"
  mkdir -p "$bindir"
  dpkg-scanpackages --multiversion --arch "$arch" pool > "$bindir/Packages"
  gzip -n -9 -c "$bindir/Packages" > "$bindir/Packages.gz"
done

apt-ftparchive \
  -o "APT::FTPArchive::Release::Origin=op-go" \
  -o "APT::FTPArchive::Release::Label=op-go" \
  -o "APT::FTPArchive::Release::Suite=$SUITE" \
  -o "APT::FTPArchive::Release::Codename=$SUITE" \
  -o "APT::FTPArchive::Release::Architectures=$ARCHES" \
  -o "APT::FTPArchive::Release::Components=$COMPONENT" \
  -o "APT::FTPArchive::Release::ValidTime=$VALID_SECONDS" \
  release "dists/$SUITE" > "dists/$SUITE/Release"

gpg --batch --yes --local-user "$KEY" --armor --detach-sign \
  --output "dists/$SUITE/Release.gpg" "dists/$SUITE/Release"
gpg --batch --yes --local-user "$KEY" --clearsign \
  --output "dists/$SUITE/InRelease" "dists/$SUITE/Release"
gpg --batch --armor --export "$KEY" > op-go.asc

cat > index.html <<EOF
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>op-go apt repository</title></head>
<body><h1>op-go apt repository</h1>
<p>Signed apt repository for <a href="https://github.com/curtisgalloway/op-go">op-go</a>
(amd64/arm64, Debian and Ubuntu). To use it:</p>
<pre>
sudo install -d /etc/apt/keyrings
sudo curl -fsSL -o /etc/apt/keyrings/op-go.asc $BASE_URL/op-go.asc
sudo tee /etc/apt/sources.list.d/op-go.sources &gt;/dev/null &lt;&lt;'SRC'
Types: deb
URIs: $BASE_URL
Suites: $SUITE
Components: $COMPONENT
Signed-By: /etc/apt/keyrings/op-go.asc
SRC
sudo apt update &amp;&amp; sudo apt install op-go
</pre>
<p>Signing key fingerprint: <code>$FPR</code></p>
</body></html>
EOF

echo "apt repo assembled in $OUT:"
find . -type f | sort
