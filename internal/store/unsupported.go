//go:build !darwin && !linux

// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package store

import "context"

type fileStore struct{ path string }
type nativeStore struct{ backend, path string }

func (fileStore) Status(context.Context) (bool, error)        { return false, ErrUnavailable }
func (fileStore) Read(context.Context) (string, error)        { return "", ErrUnavailable }
func (fileStore) Write(context.Context, string, bool) error   { return ErrUnavailable }
func (fileStore) Delete(context.Context) error                { return ErrUnavailable }
func (nativeStore) Status(context.Context) (bool, error)      { return false, ErrUnavailable }
func (nativeStore) Read(context.Context) (string, error)      { return "", ErrUnavailable }
func (nativeStore) Write(context.Context, string, bool) error { return ErrUnavailable }
func (nativeStore) Delete(context.Context) error              { return ErrUnavailable }
func Worker(args []string) (bool, int) {
	if len(args) > 0 && args[0] == "--internal-credential-worker" {
		return true, 3
	}
	return false, 0
}
