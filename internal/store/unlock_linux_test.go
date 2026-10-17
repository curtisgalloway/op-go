// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
)

type FakeUnlock struct {
	fake         *FakeSecretService
	failure      string
	remainLocked bool
}

func (u *FakeUnlock) UnlockWithMasterPassword(collection dbus.ObjectPath, value secret) *dbus.Error {
	u.fake.mu.Lock()
	defer u.fake.mu.Unlock()
	u.fake.record("UnlockWithMasterPassword")
	if collection != fakeCollection || value.Session != fakeSession || string(value.Value) != "password-sentinel" || len(value.Parameters) != 0 {
		return dbus.NewError("org.freedesktop.Secret.Error.IsLocked", nil)
	}
	if u.failure != "" {
		return dbus.NewError(u.failure, []any{"password-sentinel"})
	}
	u.fake.locked = u.remainLocked
	return nil
}

func TestUnlockPasswordExtension(t *testing.T) {
	for _, tc := range []struct {
		name, failure string
		remainLocked  bool
		want          error
	}{
		{name: "success"},
		{name: "wrong password", failure: "org.gnome.keyring.Error.Denied", want: ErrLocked},
		{name: "denied", failure: "org.freedesktop.DBus.Error.AccessDenied", want: ErrDenied},
		{name: "still locked", remainLocked: true, want: ErrLocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := privateSecretService(t)
			f.mu.Lock()
			f.loginAlias = true
			f.locked = true
			f.mu.Unlock()
			if _, err := f.conn.RequestName("org.gnome.keyring", dbus.NameFlagDoNotQueue); err != nil {
				t.Fatal(err)
			}
			u := &FakeUnlock{fake: f, failure: tc.failure, remainLocked: tc.remainLocked}
			if err := f.conn.Export(u, secretRoot, gnomeUnlockInterface); err != nil {
				t.Fatal(err)
			}
			node := &introspect.Node{Interfaces: []introspect.Interface{{Name: gnomeUnlockInterface, Methods: introspect.Methods(u)}}}
			if err := f.conn.Export(introspect.NewIntrospectable(node), secretRoot, "org.freedesktop.DBus.Introspectable"); err != nil {
				t.Fatal(err)
			}
			if err := unlockOperation(context.Background(), request{Backend: "secret-service", Operation: "unlock-check"}); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			calls := f.calls["OpenSession"] + f.calls["UnlockWithMasterPassword"]
			f.mu.Unlock()
			if calls != 0 {
				t.Fatal("preflight accessed password session")
			}
			s, err := Open("secret-service", "")
			if err != nil {
				t.Fatal(err)
			}
			if err = s.(Unlocker).Unlock(context.Background(), []byte("password-sentinel")); !errors.Is(err, tc.want) {
				t.Fatalf("unlock: %v", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.calls["UnlockWithMasterPassword"] != 1 || f.calls["GetSecret"] != 0 || f.calls["Prompt"] != 0 {
				t.Fatalf("unexpected operations: %v", f.calls)
			}
		})
	}
}

func TestUnlockRejectsNonGNOMEService(t *testing.T) {
	privateSecretService(t)
	if err := unlockOperation(context.Background(), request{Backend: "secret-service", Operation: "unlock-check"}); err != ErrUnavailable {
		t.Fatalf("unexpected check: %v", err)
	}
}

func TestPasswordUnlockSignature(t *testing.T) {
	good := `<node><interface name="` + gnomeUnlockInterface + `"><method name="UnlockWithMasterPassword"><arg type="o" direction="in"/><arg type="(oayays)" direction="in"/></method></interface></node>`
	if !hasPasswordUnlock(good) {
		t.Fatal("valid signature rejected")
	}
	for _, s := range []string{"", `<node>`, `<node><interface name="` + gnomeUnlockInterface + `"><method name="UnlockWithMasterPassword"><arg type="o"/><arg type="(oayays)" direction="out"/></method></interface></node>`} {
		if hasPasswordUnlock(s) {
			t.Fatal("invalid signature accepted")
		}
	}
}

func TestUnlockDeadline(t *testing.T) {
	f := privateSecretService(t)
	if _, err := f.conn.RequestName("org.gnome.keyring", dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.delay = 100 * time.Millisecond
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := unlockOperation(ctx, request{Backend: "secret-service", Operation: "unlock-check"}); err == nil {
		t.Fatal("stalled check succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("deadline not enforced")
	}
}

func exposePasswordUnlock(t *testing.T, f *FakeSecretService) {
	t.Helper()
	owner, err := f.conn.RequestName("org.gnome.keyring", dbus.NameFlagDoNotQueue)
	if err != nil || owner != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal("cannot own fake GNOME name")
	}
	u := &FakeUnlock{fake: f}
	if err := f.conn.Export(u, secretRoot, gnomeUnlockInterface); err != nil {
		t.Fatal(err)
	}
	node := &introspect.Node{Interfaces: []introspect.Interface{{Name: gnomeUnlockInterface, Methods: introspect.Methods(u)}}}
	if err := f.conn.Export(introspect.NewIntrospectable(node), secretRoot, "org.freedesktop.DBus.Introspectable"); err != nil {
		t.Fatal(err)
	}
}

func assertNoPasswordSession(t *testing.T, f *FakeSecretService) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, name := range []string{"OpenSession", "UnlockWithMasterPassword", "Prompt", "GetSecret"} {
		if f.calls[name] != 0 {
			t.Errorf("unexpected %s call", name)
		}
	}
}

func TestUnlockRejectsMismatchedBusOwners(t *testing.T) {
	f := privateSecretService(t)
	other, err := dbus.Connect(os.Getenv("DBUS_SESSION_BUS_ADDRESS"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	owner, err := other.RequestName("org.gnome.keyring", dbus.NameFlagDoNotQueue)
	if err != nil || owner != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal("cannot own distinct fake GNOME name")
	}
	for _, op := range []string{"unlock-check", "unlock"} {
		err := unlockOperation(context.Background(), request{Backend: "secret-service", Operation: op, Password: []byte("password-sentinel")})
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s: %v", op, err)
		}
	}
	assertNoPasswordSession(t, f)
}

func TestUnlockRejectsNonLoginDefaultCollection(t *testing.T) {
	for _, path := range []dbus.ObjectPath{"/", "/org/freedesktop/secrets/collection/other"} {
		t.Run(string(path), func(t *testing.T) {
			f := privateSecretService(t)
			exposePasswordUnlock(t, f)
			f.mu.Lock()
			f.loginPath = path
			f.mu.Unlock()
			for _, op := range []string{"unlock-check", "unlock"} {
				err := unlockOperation(context.Background(), request{Backend: "secret-service", Operation: op, Password: []byte("password-sentinel")})
				if !errors.Is(err, ErrUnavailable) {
					t.Fatalf("%s: %v", op, err)
				}
			}
			assertNoPasswordSession(t, f)
		})
	}
}

func TestUnlockRejectsInvalidPasswordBeforeSession(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password []byte
	}{
		{"empty", nil}, {"NUL", []byte("fake\x00password")}, {"oversized", bytes.Repeat([]byte("x"), maxToken+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := privateSecretService(t)
			exposePasswordUnlock(t, f)
			f.mu.Lock()
			f.loginAlias = true
			f.locked = true
			f.mu.Unlock()
			err := unlockOperation(context.Background(), request{Backend: "secret-service", Operation: "unlock", Password: tc.password})
			if !errors.Is(err, ErrInvalidFile) {
				t.Fatalf("invalid password: %v", err)
			}
			assertNoPasswordSession(t, f)
		})
	}
}
