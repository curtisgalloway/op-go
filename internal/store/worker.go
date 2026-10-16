//go:build darwin || linux

// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const workerFlag = "--internal-credential-worker"

type request struct {
	Backend   string
	Path      string
	Operation string
	Token     string
	Replace   bool
}
type response struct {
	Present bool
	Token   string
	Error   int
}

// nativeStore isolates every source, including potentially stalled filesystems.
type nativeStore struct{ backend, path string }

var safeErrors = []error{nil, ErrUnavailable, ErrLocked, ErrNotFound, ErrDenied, ErrExists, ErrInvalidFile, context.Canceled, context.DeadlineExceeded, ErrOutcomeUnknown}

func errorCode(err error) int {
	for i, e := range safeErrors {
		if errors.Is(err, e) {
			return i
		}
	}
	return 1
}
func (s nativeStore) call(ctx context.Context, req request) (response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		return response{}, ErrUnavailable
	}
	req.Backend = s.backend
	req.Path = s.path
	return callWorker(ctx, executable, []string{workerFlag}, req)
}
func callWorker(ctx context.Context, executable string, args []string, req request) (response, error) {
	if err := ctx.Err(); err != nil {
		return response{}, err
	}
	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		return response{}, ErrUnavailable
	}
	defer inputRead.Close()
	defer inputWrite.Close()
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		return response{}, ErrUnavailable
	}
	defer outputRead.Close()
	defer outputWrite.Close()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.WaitDelay = 100 * time.Millisecond
	cmd.ExtraFiles = []*os.File{inputRead, outputWrite}
	cmd.Env = cleanEnvironment(os.Environ())
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Start() != nil {
		if err := ctx.Err(); err != nil {
			return response{}, err
		}
		return response{}, ErrUnavailable
	}
	inputRead.Close()
	outputWrite.Close()
	// Closing the pipes also bounds reads/writes if a child stalls or forks.
	stop := context.AfterFunc(ctx, func() { inputWrite.Close(); outputRead.Close() })
	defer stop()
	sent := make(chan error, 1)
	go func() { err := json.NewEncoder(inputWrite).Encode(req); inputWrite.Close(); sent <- err }()
	var result response
	decodeErr := json.NewDecoder(io.LimitReader(outputRead, 8*maxToken+4096)).Decode(&result)
	if decodeErr != nil {
		cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	inputWrite.Close()
	sendErr := <-sent
	if err := ctx.Err(); err != nil {
		return response{}, err
	}
	if decodeErr != nil || waitErr != nil || sendErr != nil || result.Error < 0 || result.Error >= len(safeErrors) {
		if req.Operation == "write" || req.Operation == "delete" {
			return response{}, ErrOutcomeUnknown
		}
		return response{}, ErrUnavailable
	}
	if result.Error != 0 {
		return response{}, safeErrors[result.Error]
	}
	if req.Operation == "read" {
		token, err := NormalizeToken(result.Token)
		if err != nil {
			return response{}, err
		}
		result.Token = token
	} else {
		result.Token = ""
	}
	return result, nil
}
func cleanEnvironment(env []string) []string {
	out := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if key == "OP_SERVICE_ACCOUNT_TOKEN" || key == "OP_CONNECT_TOKEN" || strings.HasPrefix(key, "OP_SESSION_") {
			continue
		}
		out = append(out, entry)
	}
	return out
}
func (s nativeStore) Status(ctx context.Context) (bool, error) {
	r, e := s.call(ctx, request{Operation: "status"})
	return r.Present, e
}
func (s nativeStore) Read(ctx context.Context) (string, error) {
	r, e := s.call(ctx, request{Operation: "read"})
	return r.Token, e
}
func (s nativeStore) Write(ctx context.Context, token string, replace bool) error {
	if s.backend == "file" {
		return ErrDenied
	}
	token, e := NormalizeToken(token)
	if e != nil {
		return e
	}
	_, e = s.call(ctx, request{Operation: "write", Token: token, Replace: replace})
	return e
}
func (s nativeStore) Delete(ctx context.Context) error {
	if s.backend == "file" {
		return ErrDenied
	}
	_, e := s.call(ctx, request{Operation: "delete"})
	return e
}

// Worker handles only the private pipe protocol. It never writes to stdio.
func Worker(args []string) (bool, int) {
	if len(args) == 0 || args[0] != workerFlag {
		return false, 0
	}
	if len(args) != 1 {
		return true, 2
	}
	in := os.NewFile(3, "request")
	out := os.NewFile(4, "response")
	defer in.Close()
	defer out.Close()
	for _, f := range []*os.File{in, out} {
		st, err := f.Stat()
		if err != nil || st.Mode()&os.ModeNamedPipe == 0 {
			return true, 2
		}
		syscall.CloseOnExec(int(f.Fd()))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var req request
	if json.NewDecoder(io.LimitReader(in, 8*maxToken+4096)).Decode(&req) != nil {
		return true, 2
	}
	result, err := workerOperation(ctx, req)
	if err != nil {
		result = response{Error: errorCode(err)}
	}
	if req.Operation != "read" {
		result.Token = ""
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return true, 3
	}
	return true, 0
}

func workerOperation(ctx context.Context, req request) (response, error) {
	if req.Backend != "file" {
		return nativeOperation(ctx, req)
	}
	if req.Path == "" {
		return response{}, ErrInvalidFile
	}
	s := fileStore{req.Path}
	switch req.Operation {
	case "status":
		present, err := s.Status(ctx)
		return response{Present: present}, err
	case "read":
		token, err := s.Read(ctx)
		return response{Token: token}, err
	case "write", "delete":
		return response{}, ErrDenied
	default:
		return response{}, ErrUnavailable
	}
}
