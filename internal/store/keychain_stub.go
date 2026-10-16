//go:build darwin && !cgo

// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package store

import "context"

func nativeOperation(ctx context.Context, _ request) (response, error) {
	if err := ctx.Err(); err != nil {
		return response{}, err
	}
	return response{}, ErrUnavailable
}
