//go:build darwin

// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package store

import "context"

func unlockOperation(context.Context, request) error { return ErrUnavailable }
