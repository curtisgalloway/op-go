#!/bin/bash
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
version="${OP_GO_VERSION:?Set OP_GO_VERSION}"
commit="${OP_GO_COMMIT:?Set OP_GO_COMMIT}"
date="${OP_GO_DATE:?Set OP_GO_DATE}"
arch="${1:?Usage: build-linux.sh amd64|arm64 output}"
output="${2:?Specify the output file}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ "$commit" =~ ^[0-9a-f]{40}$ ]]
[[ "$date" =~ ^[0-9TZ:-]+$ ]]
[[ "$arch" == amd64 || "$arch" == arm64 ]]
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
    -ldflags "-X github.com/curtisgalloway/op-go/internal/cli.Version=$version -X github.com/curtisgalloway/op-go/internal/cli.Commit=$commit -X github.com/curtisgalloway/op-go/internal/cli.Date=$date" \
    -o "$output" ./cmd/op-go
