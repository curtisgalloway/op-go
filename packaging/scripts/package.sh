#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
exec python3 "${BASH_SOURCE[0]%/*}/package.py" "$@"
