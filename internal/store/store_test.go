//go:build darwin || linux

// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Re-enter the private worker exactly as main does, using only temporary files
// in these tests. No test invokes a native credential source through this path.
func TestMain(m *testing.M) {
	if handled, code := Worker(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func TestProtectedFile(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("sentinel\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := fileStore{path}
	if ok, err := s.Status(context.Background()); !ok || err != nil {
		t.Fatalf("status: %v %v", ok, err)
	}
	if token, err := s.Read(context.Background()); token != "sentinel" || err != nil {
		t.Fatal("read failed")
	}
	if err := s.Write(context.Background(), "new", true); err != ErrDenied {
		t.Fatal(err)
	}
	if err := s.Delete(context.Background()); err != ErrDenied {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(context.Background()); err != ErrInvalidFile {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxToken+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Status(context.Background()); err != ErrInvalidFile {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Status(context.Background()); !ok || err != nil {
		t.Fatal("status should inspect metadata only")
	}
	if _, err := s.Read(context.Background()); err != ErrInvalidFile {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{link, dir} {
		source := fileStore{bad}
		if _, err := source.Read(context.Background()); err != ErrInvalidFile {
			t.Fatal("accepted symlink or directory")
		}
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	source := fileStore{fifo}
	start := time.Now()
	if _, err := source.Read(context.Background()); err != ErrInvalidFile {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("FIFO blocked")
	}
	missing := fileStore{filepath.Join(dir, "missing")}
	if ok, err := missing.Status(context.Background()); ok || err != nil {
		t.Fatal("missing status")
	}
}

func TestPublicFileSourceUsesWorker(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	path := filepath.Join(t.TempDir(), "sentinel-path")
	if err := os.WriteFile(path, []byte("sentinel\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open("file", path)
	if err != nil {
		t.Fatal(err)
	}
	if worker, ok := s.(nativeStore); !ok || worker.path != path || worker.backend != "file" {
		t.Fatal("file source bypasses isolated worker")
	}
	if present, err := s.Status(context.Background()); err != nil || !present {
		t.Fatalf("worker metadata: %v", err)
	}
	if token, err := s.Read(context.Background()); err != nil || token != "sentinel" {
		t.Fatalf("worker read: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Status(ctx); err != context.Canceled {
		t.Fatal("file status ignored cancellation")
	}
	if _, err := s.Read(ctx); err != context.Canceled {
		t.Fatal("file read ignored cancellation")
	}
	if err := s.Write(ctx, "", false); err != ErrDenied {
		t.Fatal("file mutation must reject without launching worker")
	}
	if err := s.Delete(ctx); err != ErrDenied {
		t.Fatal("file deletion must reject without launching worker")
	}
}

func TestTokenValidation(t *testing.T) {
	for _, value := range []string{"", "\n", "x\n\n", "x\r", "x\x00", "x\ny", "x\t", "x\x7f", "x\u0085", "x\xff", strings.Repeat("x", maxToken+1)} {
		if _, err := NormalizeToken(value); err != ErrInvalidFile {
			t.Fatal("accepted malformed token")
		}
	}
	for _, value := range []string{"x", "x\n", "x\r\n"} {
		if got, err := NormalizeToken(value); got != "x" || err != nil {
			t.Fatal("normalization failed")
		}
	}
}

// TestWorkerHelper is entered only by subprocess tests. No native store is used.
func TestWorkerHelper(t *testing.T) {
	args := os.Args
	marker := -1
	for i, arg := range args {
		if arg == "--fake-store" {
			marker = i
			break
		}
	}
	if marker < 0 {
		return
	}
	mode := args[marker+1]
	if mode == "stall" {
		time.Sleep(time.Minute)
		os.Exit(1)
	}
	in := os.NewFile(3, "request")
	out := os.NewFile(4, "response")
	var req request
	if json.NewDecoder(in).Decode(&req) != nil {
		os.Exit(1)
	}
	if mode == "deadline" {
		json.NewEncoder(out).Encode(response{Error: errorCode(context.DeadlineExceeded)})
		os.Exit(0)
	}
	if mode == "response-stall" {
		json.NewEncoder(out).Encode(response{})
		time.Sleep(time.Minute)
		os.Exit(1)
	}
	for _, arg := range os.Args {
		if strings.Contains(arg, "sentinel") {
			os.Exit(2)
		}
	}
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "OP_SERVICE_ACCOUNT_TOKEN=") || strings.HasPrefix(env, "OP_SESSION_") || strings.HasPrefix(env, "OP_CONNECT_TOKEN=") {
			os.Exit(3)
		}
	}
	if mode == "invalid" {
		out.Write([]byte("invalid sentinel"))
		os.Exit(0)
	}
	if mode == "crash" {
		os.Exit(1)
	}
	if mode == "out-of-range" {
		json.NewEncoder(out).Encode(response{Error: 999})
		os.Exit(0)
	}
	if mode == "denied" {
		json.NewEncoder(out).Encode(response{Error: errorCode(ErrDenied)})
		os.Exit(0)
	}
	if req.Token != "sentinel" {
		os.Exit(4)
	}
	json.NewEncoder(out).Encode(response{Token: req.Token})
	os.Exit(0)
}

func TestWorkerPrivatePipesAndTimeout(t *testing.T) {
	// Race-instrumented subprocesses otherwise sleep one second at os.Exit.
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "sentinel")
	t.Setenv("OP_CONNECT_TOKEN", "sentinel")
	t.Setenv("OP_SESSION_test", "sentinel")
	for _, mode := range []string{"echo", "invalid", "stall"} {
		t.Run(mode, func(t *testing.T) {
			timeout := 3 * time.Second
			if mode == "stall" {
				timeout = 200 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			start := time.Now()
			r, err := callWorker(ctx, executable, []string{"-test.run=^TestWorkerHelper$", "--", "--fake-store", mode}, request{Operation: "read", Token: "sentinel"})
			if mode == "echo" {
				if err != nil || r.Token != "sentinel" {
					t.Fatal("private pipe roundtrip failed")
				}
			} else if mode == "stall" && err != context.DeadlineExceeded {
				t.Fatal("worker deadline was not preserved")
			} else if mode != "stall" && err != ErrUnavailable {
				t.Fatal("unsafe worker error")
			}
			if time.Since(start) > timeout+time.Second {
				t.Fatal("worker failed to time out")
			}
		})
	}
}

func TestMutationWorkerPreservesTimeout(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"write", "delete"} {
		for _, mode := range []string{"stall", "response-stall", "deadline"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				timeout := 200 * time.Millisecond
				if mode == "deadline" {
					timeout = 3 * time.Second
				}
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				start := time.Now()
				_, err := callWorker(ctx, executable, []string{"-test.run=^TestWorkerHelper$", "--", "--fake-store", mode}, request{Operation: operation, Token: "sentinel"})
				if err != context.DeadlineExceeded {
					t.Fatalf("want safe timeout, got %v", err)
				}
				if time.Since(start) > timeout+time.Second {
					t.Fatal("mutation worker hung")
				}
			})
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := callWorker(ctx, executable, nil, request{Operation: "write"}); err != context.Canceled {
		t.Fatal("cancellation was not preserved")
	}
	if _, err := nativeOperation(ctx, request{}); err != context.Canceled {
		t.Fatal("native cancellation was not preserved")
	}
}

func TestLostMutationResponseIsUnknown(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"write", "delete", "read"} {
		for _, mode := range []string{"invalid", "crash", "out-of-range", "denied"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_, err := callWorker(ctx, executable, []string{"-test.run=^TestWorkerHelper$", "--", "--fake-store", mode}, request{Operation: operation, Token: "sentinel"})
				want := ErrOutcomeUnknown
				if operation == "read" {
					want = ErrUnavailable
				}
				if mode == "denied" {
					want = ErrDenied
				}
				if err != want {
					t.Fatalf("want %v, got %v", want, err)
				}
			})
		}
	}
}

func TestWorkerErrorCodesAreSanitized(t *testing.T) {
	if safeErrors[errorCode(errors.New("sentinel secret"))] != ErrUnavailable {
		t.Fatal("raw error escaped")
	}
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, ErrDenied, ErrOutcomeUnknown} {
		if got := safeErrors[errorCode(fmt.Errorf("sentinel secret: %w", err))]; got != err {
			t.Fatal("wrapped safe error not preserved")
		}
	}
}

func TestWorkerRejectsInvocationWithoutPipes(t *testing.T) {
	if handled, code := Worker([]string{workerFlag, "token"}); !handled || code != 2 {
		t.Fatal("worker accepted arguments")
	}
	if handled, _ := Worker([]string{"doctor"}); handled {
		t.Fatal("worker intercepted normal command")
	}
}
