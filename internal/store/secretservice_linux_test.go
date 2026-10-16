// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

const fakeCollection = dbus.ObjectPath("/org/freedesktop/secrets/collection/test")
const fakeItem = dbus.ObjectPath("/org/freedesktop/secrets/collection/test/item")
const fakeSession = dbus.ObjectPath("/org/freedesktop/secrets/session/test")

// FakeSecretService lives exclusively on a dedicated test bus. Its counters
// make forbidden value reads and interactive operations observable.
type FakeSecretService struct {
	mu              sync.Mutex
	calls           map[string]int
	token           string
	count           int
	locked          bool
	failure         string
	mutationFailure string
	delay           time.Duration
}

func (f *FakeSecretService) record(name string) { f.calls[name]++ }
func (f *FakeSecretService) ReadAlias(alias string) (dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	f.record("ReadAlias")
	delay, failure := f.delay, f.failure
	f.mu.Unlock()
	time.Sleep(delay)
	if failure != "" {
		return "/", dbus.NewError(failure, []any{"sentinel secret error"})
	}
	if alias != "default" {
		return "/", nil
	}
	return fakeCollection, nil
}
func (f *FakeSecretService) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Get")
	if property != "Locked" {
		return dbus.MakeVariant(false), dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", nil)
	}
	return dbus.MakeVariant(f.locked), nil
}
func (f *FakeSecretService) SearchItems(attrs map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("SearchItems")
	if attrs["service"] != "op-go" || attrs["account"] != "service-account" {
		return nil, dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", nil)
	}
	items := []dbus.ObjectPath{}
	for i := 0; i < f.count; i++ {
		items = append(items, fakeItem)
	}
	return items, nil
}
func (f *FakeSecretService) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("OpenSession")
	if algorithm != "plain" || input.Value() != "" {
		return dbus.MakeVariant(""), "/", dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", nil)
	}
	return dbus.MakeVariant(""), fakeSession, nil
}
func (f *FakeSecretService) GetSecret(session dbus.ObjectPath) (secret, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GetSecret")
	return secret{session, []byte{}, []byte(f.token), "text/plain; charset=utf-8"}, nil
}
func (f *FakeSecretService) CreateItem(properties map[string]dbus.Variant, value secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("CreateItem")
	if f.mutationFailure != "" {
		return "/", "/", dbus.NewError(f.mutationFailure, []any{"sentinel secret"})
	}
	attrs, ok := properties["org.freedesktop.Secret.Item.Attributes"].Value().(map[string]string)
	if !ok || attrs["service"] != "op-go" || attrs["account"] != "service-account" || value.Session != fakeSession || len(value.Parameters) != 0 {
		return "/", "/", dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", nil)
	}
	if f.count != 0 && !replace {
		f.count++
	} else {
		f.count = 1
	}
	f.token = string(value.Value)
	return fakeItem, "/", nil
}
func (f *FakeSecretService) Delete() (dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Delete")
	if f.mutationFailure != "" {
		return "/", dbus.NewError(f.mutationFailure, []any{"sentinel secret"})
	}
	f.token = ""
	f.count = 0
	return "/", nil
}
func (f *FakeSecretService) Close() *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Close")
	return nil
}
func (f *FakeSecretService) Unlock(items []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Unlock")
	return nil, "/", nil
}
func (f *FakeSecretService) Prompt(window string) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("Prompt")
	return nil
}

func privateSecretService(t *testing.T) *FakeSecretService {
	t.Helper()
	executable, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("private Secret Service test requires dbus-daemon")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, executable, "--session", "--nofork", "--print-address=1", "--address=unix:tmpdir=/tmp")
	cmd.Env = cleanEnvironment(os.Environ())
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		cancel()
		t.Fatal("private bus failed to start")
	}
	t.Cleanup(func() { cancel(); cmd.Wait() })
	address, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal("private bus did not provide address")
	}
	address = strings.TrimSpace(address)
	if !strings.HasPrefix(address, "unix:") {
		t.Fatal("private bus is not local")
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", address)
	conn, err := dbus.Connect(address)
	if err != nil {
		t.Fatal("cannot connect to private bus")
	}
	t.Cleanup(func() { conn.Close() })
	fake := &FakeSecretService{calls: map[string]int{}, token: "sentinel", count: 1}
	for _, entry := range []struct {
		path  dbus.ObjectPath
		iface string
	}{
		{secretRoot, "org.freedesktop.Secret.Service"},
		{fakeCollection, "org.freedesktop.Secret.Collection"},
		{fakeCollection, "org.freedesktop.DBus.Properties"},
		{fakeItem, "org.freedesktop.Secret.Item"},
		{fakeItem, "org.freedesktop.DBus.Properties"},
		{fakeSession, "org.freedesktop.Secret.Session"},
		{dbus.ObjectPath("/org/freedesktop/secrets/prompt/test"), "org.freedesktop.Secret.Prompt"},
	} {
		if err := conn.Export(fake, entry.path, entry.iface); err != nil {
			t.Fatal(err)
		}
	}
	owner, err := conn.RequestName(secretBus, dbus.NameFlagDoNotQueue)
	if err != nil || owner != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal("cannot own fake Secret Service name")
	}
	return fake
}

func TestSecretServicePrivateBus(t *testing.T) {
	fake := privateSecretService(t)
	run := func(operation string, replace bool) (response, error) {
		return nativeOperation(context.Background(), request{Backend: "secret-service", Operation: operation, Token: "dummy-new-token", Replace: replace})
	}
	if result, err := run("status", false); err != nil || !result.Present {
		t.Fatalf("status: %v", err)
	}
	fake.mu.Lock()
	reads, sessions := fake.calls["GetSecret"], fake.calls["OpenSession"]
	fake.mu.Unlock()
	if reads != 0 || sessions != 0 {
		t.Fatal("metadata status retrieved secrets")
	}
	if result, err := run("read", false); err != nil || result.Token != "sentinel" {
		t.Fatalf("read: %v", err)
	}
	if _, err := run("write", false); err != ErrExists {
		t.Fatalf("overwrite without consent: %v", err)
	}
	if _, err := run("write", true); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if result, err := run("read", false); err != nil || result.Token != "dummy-new-token" {
		t.Fatalf("replaced read: %v", err)
	}
	if _, err := run("delete", false); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if result, err := run("status", false); err != nil || result.Present {
		t.Fatalf("missing status: %v", err)
	}
	if _, err := run("read", false); err != ErrNotFound {
		t.Fatalf("missing read: %v", err)
	}
	if _, err := run("write", false); err != nil {
		t.Fatalf("create: %v", err)
	}
	fake.mu.Lock()
	fake.locked = true
	fake.mu.Unlock()
	for _, operation := range []string{"status", "read", "write", "delete"} {
		if _, err := run(operation, true); err != ErrLocked {
			t.Fatalf("locked %s: %v", operation, err)
		}
	}
	fake.mu.Lock()
	prompts, unlocks := fake.calls["Prompt"], fake.calls["Unlock"]
	fake.locked = false
	fake.count = 2
	fake.mu.Unlock()
	if prompts != 0 || unlocks != 0 {
		t.Fatal("attempted interactive unlock")
	}
	for _, operation := range []string{"status", "read", "write", "delete"} {
		if _, err := run(operation, true); err != ErrDenied {
			t.Fatalf("ambiguous %s: %v", operation, err)
		}
	}
	fake.mu.Lock()
	fake.count = 1
	fake.failure = "org.freedesktop.DBus.Error.AccessDenied"
	fake.mu.Unlock()
	if _, err := run("read", false); err != ErrDenied {
		t.Fatalf("access failure not sanitized: %v", err)
	}
	fake.mu.Lock()
	fake.failure = "org.example.Unexpected"
	fake.mu.Unlock()
	if _, err := run("read", false); err != ErrUnavailable {
		t.Fatalf("unexpected failure not sanitized: %v", err)
	}
	fake.mu.Lock()
	fake.failure = ""
	fake.mu.Unlock()
	for _, test := range []struct {
		name string
		want error
	}{
		{"org.example.TransportLost", ErrOutcomeUnknown},
		{"org.freedesktop.DBus.Error.AccessDenied", ErrDenied},
		{"org.freedesktop.Secret.Error.IsLocked", ErrLocked},
		{"org.freedesktop.Secret.Error.NoSuchObject", ErrNotFound},
	} {
		fake.mu.Lock()
		fake.mutationFailure = test.name
		fake.mu.Unlock()
		for _, operation := range []string{"write", "delete"} {
			if _, err := run(operation, true); err != test.want {
				t.Fatalf("mutation %s: want %v, got %v", operation, test.want, err)
			}
		}
	}
	fake.mu.Lock()
	fake.mutationFailure = ""
	fake.delay = 300 * time.Millisecond
	fake.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := nativeOperation(ctx, request{Backend: "secret-service", Operation: "write", Token: "dummy"}); err != context.DeadlineExceeded {
		t.Fatalf("deadline: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("private service timeout was not bounded")
	}
}
