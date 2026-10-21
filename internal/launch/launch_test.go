// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fakeStore struct{ reads int }

func (s *fakeStore) Status(context.Context) (bool, error) { return true, nil }
func (s *fakeStore) Read(context.Context) (string, error) {
	s.reads++
	return "dummy-service-token", nil
}
func (s *fakeStore) Write(context.Context, string, bool) error { return nil }
func (s *fakeStore) Delete(context.Context) error              { return nil }

type fakeResolver struct{ fail bool }

func (r fakeResolver) Resolve(_ context.Context, ref string) (string, error) {
	if r.fail || strings.HasSuffix(ref, "bad") {
		return "", errors.New("dummy-service-token and private response")
	}
	return "application-secret", nil
}
func factoryOK(context.Context, string) (resolver, error) { return fakeResolver{}, nil }

func TestParseLiteralAndReferences(t *testing.T) {
	entries, err := parse(strings.NewReader("# comment\r\nA=  $HOME # kept\r\nB=\"literal\"\nC=op://vault/item/field\n"))
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].value != "  $HOME # kept" || entries[1].value != `"literal"` || !entries[2].reference {
		t.Fatalf("unexpected parse: %#v", entries)
	}
}
func TestParseRejectsUnsafeAndMalformed(t *testing.T) {
	for _, input := range []string{"A=1\nA=2", "OP_SERVICE_ACCOUNT_TOKEN=x", "OP_CONNECT_TOKEN=x", "OP_SESSION_example=x", "export A=x", " A=x", "A =x", "=x", "1A=x", "A=bad\x00value", "A=prefix-op://v/i/f", "A=op://v/i", "A=op://v//f", "A=op://v/i/%00", "A=op://v/i/%zz", strings.Repeat("x", maxEnvSize+1)} {
		_, err := parse(strings.NewReader(input))
		if err == nil {
			t.Errorf("accepted invalid entry")
		}
		if err != nil && strings.Contains(err.Error(), "bad\x00value") {
			t.Fatal("leaked input")
		}
	}
}
func TestResolutionAllOrNothingAndRedaction(t *testing.T) {
	for _, fail := range []bool{false, true} {
		p := &Prepared{path: "/bin/true", command: []string{"true"}, inherited: []string{"BASE=kept", "OP_CONNECT_TOKEN=removed", "OP_SESSION_a=removed"}, entries: []entry{{"A", "op://v/i/f", true}, {"B", "literal", false}}}
		s := &fakeStore{}
		called := false
		err := p.run(context.Background(), s, time.Second, func(context.Context, string) (resolver, error) { return fakeResolver{fail}, nil }, func(_ string, _ []string, env []string) error {
			called = true
			if !reflect.DeepEqual(env, []string{"A=application-secret", "B=literal", "BASE=kept"}) {
				t.Errorf("unexpected env: %v", env)
			}
			return nil
		})
		if called == fail {
			t.Fatal("launch occurred on failure or failed to occur on success")
		}
		if fail && (err == nil || strings.Contains(err.Error(), "dummy-service-token")) {
			t.Fatal("missing or unsafe diagnostic")
		}
		if s.reads != 1 {
			t.Fatal("unexpected token reads")
		}
	}
}
func TestNoReferencesDoesNotReadToken(t *testing.T) {
	p := &Prepared{path: "/bin/true", command: []string{"true"}, entries: []entry{{"A", "literal", false}}}
	s := &fakeStore{}
	err := p.run(context.Background(), s, time.Second, factoryOK, func(string, []string, []string) error { return nil })
	if err != nil || s.reads != 0 {
		t.Fatalf("error=%v reads=%d", err, s.reads)
	}
}
func TestInheritedTokenRefused(t *testing.T) {
	p := &Prepared{inherited: []string{"OP_SERVICE_ACCOUNT_TOKEN="}}
	s := &fakeStore{}
	err := p.run(context.Background(), s, time.Second, factoryOK, func(string, []string, []string) error { t.Fatal("executed"); return nil })
	if err == nil || s.reads != 0 {
		t.Fatal("inherited token accepted")
	}
}
func TestInitializationTimeoutNeverExecutes(t *testing.T) {
	p := &Prepared{entries: []entry{{"A", "op://v/i/f", true}}}
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	err := p.run(context.Background(), &fakeStore{}, 10*time.Millisecond, func(context.Context, string) (resolver, error) { <-release; return fakeResolver{}, nil }, func(string, []string, []string) error { t.Error("executed after timeout"); return nil })
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != 20 || time.Since(start) > time.Second {
		t.Fatalf("timeout failed: %v", err)
	}
}
func TestOriginalPathAndNoFIFOBlocking(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "env")
	if err := os.WriteFile(env, []byte("PATH=/not/the/original/path\n"), 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := Prepare(env, []string{"sh"})
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(plan.Summary().Executable) {
		t.Fatal("not absolute")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(fifo, []string{"sh"}); err == nil {
		t.Fatal("accepted FIFO")
	}
}
func TestExecProcessHelper(t *testing.T) {
	if os.Getenv("OP_GO_TEST_EXEC") != "1" {
		return
	}
	mode := os.Getenv("OP_GO_TEST_MODE")
	if mode == "replace" {
		// Descriptor 3 was deliberately inherited without close-on-exec.
		if err := replace(os.Args[0], []string{os.Args[0], "-test.run=^TestExecProcessHelper$"}, []string{"OP_GO_TEST_EXEC=1", "OP_GO_TEST_MODE=child", "OP_GO_TEST_INODE=" + os.Getenv("OP_GO_TEST_INODE")}); err != nil {
			os.Exit(98)
		}
	} else if mode == "child" {
		var info unix.Stat_t
		if unix.Fstat(3, &info) == nil && strconv.FormatUint(uint64(info.Ino), 10) == os.Getenv("OP_GO_TEST_INODE") {
			os.Exit(97)
		}
		if os.Getenv("OP_SERVICE_ACCOUNT_TOKEN") != "" {
			os.Exit(96)
		}
		os.Exit(42)
	} else if mode == "signal" {
		if err := replace("/bin/sh", []string{"sh", "-c", "kill -TERM $$"}, []string{}); err != nil {
			os.Exit(98)
		}
	} else if mode == "network" {
		// SDK resolution starts Go's network poller. On macOS its kqueue appears in
		// /dev/fd but cannot be stat'ed, which broke exec after every live lookup.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			os.Exit(95)
		}
		defer listener.Close()
		if err := replace("/bin/sh", []string{"sh", "-c", "exit 42"}, []string{}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(98)
		}
	}
	os.Exit(99)
}

func TestExecAfterNetworkUse(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestExecProcessHelper$")
	cmd.Env = []string{"OP_GO_TEST_EXEC=1", "OP_GO_TEST_MODE=network"}
	var out bytes.Buffer
	cmd.Stderr = &out
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 42 {
		t.Fatalf("exit=%v stderr=%s", err, out.String())
	}
}
func TestExecPreservesExitSignalAndClosesDescriptors(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fd")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestExecProcessHelper$")
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	inode := info.Sys().(*syscall.Stat_t).Ino
	cmd.Env = []string{"OP_GO_TEST_EXEC=1", "OP_GO_TEST_MODE=replace", "OP_GO_TEST_INODE=" + strconv.FormatUint(uint64(inode), 10)}
	cmd.ExtraFiles = []*os.File{f}
	var out bytes.Buffer
	cmd.Stderr = &out
	err = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 42 {
		t.Fatalf("exit=%v stderr=%s", err, out.String())
	}
	cmd = exec.Command(os.Args[0], "-test.run=^TestExecProcessHelper$")
	cmd.Env = []string{"OP_GO_TEST_EXEC=1", "OP_GO_TEST_MODE=signal"}
	err = cmd.Run()
	if !errors.As(err, &exit) {
		t.Fatalf("expected signal: %v", err)
	}
	status := exit.Sys().(syscall.WaitStatus)
	if !status.Signaled() || status.Signal() != syscall.SIGTERM {
		t.Fatalf("status %v", status)
	}
}

func TestSDKPanicIsSanitized(t *testing.T) {
	p := &Prepared{entries: []entry{{"A", "op://v/i/f", true}}}
	err := p.run(context.Background(), &fakeStore{}, time.Second,
		func(context.Context, string) (resolver, error) { panic("dummy-service-token") },
		func(string, []string, []string) error { t.Fatal("executed"); return nil })
	if err == nil || strings.Contains(err.Error(), "dummy-service-token") {
		t.Fatal("unsafe SDK panic handling")
	}
}

func TestUnsupportedReferenceNamesFailDuringPrepare(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ref, component string }{
		{"op://Test:Vault/Item/credential", "vault"},
		{"op://Vault/Item?Title/credential", "item"},
		{"op://Test Vault/Service Account: Test/credential", "item"},
		{"op://Test%20Vault/Item/credential", "vault"},
		{"op://Vault/Service%3A%20Test/credential", "item"},
		{"op://Vault/Item/Section:Test/credential", "section"},
		{"op://Vault/Item/Field:Test", "field"},
	} {
		t.Run(tc.component+tc.ref, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.env")
			if err := os.WriteFile(path, []byte("SECRET="+tc.ref+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			prepared, err := Prepare(path, []string{executable})
			var failure *Error
			if prepared != nil || !errors.As(err, &failure) || failure.Code != 2 || !strings.Contains(failure.Message, tc.component+" at line 1") || !strings.Contains(failure.Message, "ID") || strings.Contains(failure.Message, tc.ref) {
				t.Fatalf("missing actionable, sanitized preflight error: %v", err)
			}
		})
	}
}

func TestSupportedReferenceNamesAndQueries(t *testing.T) {
	for _, ref := range []string{
		"op://Test Vault/Service Account Test/credential",
		"op://vault-id/item_id/Section Name/field.name",
		"op://vault/item/field?attribute=otp",
		"op://vault/item/private_key?ssh-format=openssh",
	} {
		if _, err := parse(strings.NewReader("SECRET=" + ref)); err != nil {
			t.Fatalf("valid reference rejected: %v", err)
		}
	}
}
