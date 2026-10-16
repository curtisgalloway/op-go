// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrUnavailable    = errors.New("credential store unavailable")
	ErrLocked         = errors.New("credential store locked; unlock it separately")
	ErrNotFound       = errors.New("credential not found")
	ErrDenied         = errors.New("credential access denied")
	ErrExists         = errors.New("credential already exists")
	ErrInvalidFile    = errors.New("invalid protected credential file or token")
	ErrOutcomeUnknown = errors.New("credential mutation outcome unknown; inspect store before retrying")
)

const maxToken = 64 * 1024

type Store interface {
	Status(context.Context) (bool, error)
	Read(context.Context) (string, error)
	Write(context.Context, string, bool) error
	Delete(context.Context) error
}

func Open(backend, path string) (Store, error) {
	if backend == "" {
		switch runtime.GOOS {
		case "darwin":
			backend = "keychain"
		case "linux":
			backend = "secret-service"
		default:
			return nil, ErrUnavailable
		}
	}
	if backend == "file" {
		if path == "" {
			return nil, ErrInvalidFile
		}
		return nativeStore{backend: backend, path: path}, nil
	}
	if path != "" {
		return nil, ErrInvalidFile
	}
	if backend == "keychain" && runtime.GOOS == "darwin" || backend == "secret-service" && runtime.GOOS == "linux" {
		return nativeStore{backend: backend}, nil
	}
	return nil, ErrUnavailable
}

// NormalizeToken accepts one terminal LF or CRLF, but no control characters.
func NormalizeToken(value string) (string, error) {
	if len(value) > maxToken {
		return "", ErrInvalidFile
	}
	if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
		value = strings.TrimSuffix(value, "\r")
	}
	if value == "" || !utf8.ValidString(value) {
		return "", ErrInvalidFile
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", ErrInvalidFile
		}
	}
	return value, nil
}
