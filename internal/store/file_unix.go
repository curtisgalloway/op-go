//go:build darwin || linux

// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"io"
	"os"
	"syscall"
)

type fileStore struct{ path string }

func (s fileStore) open(ctx context.Context) (*os.File, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	fd, err := syscall.Open(s.path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if err == syscall.ENOENT {
			return nil, ErrNotFound
		}
		return nil, ErrInvalidFile
	}
	f := os.NewFile(uintptr(fd), "credential")
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || st.Size > maxToken {
		f.Close()
		return nil, ErrInvalidFile
	}
	return f, nil
}
func (s fileStore) Status(ctx context.Context) (bool, error) {
	f, err := s.open(ctx)
	if err == ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	f.Close()
	return true, nil
}
func (s fileStore) Read(ctx context.Context) (string, error) {
	f, err := s.open(ctx)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxToken+1))
	if err != nil {
		return "", ErrInvalidFile
	}
	return NormalizeToken(string(data))
}
func (s fileStore) Write(context.Context, string, bool) error { return ErrDenied }
func (s fileStore) Delete(context.Context) error              { return ErrDenied }
