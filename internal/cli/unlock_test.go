// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/curtisgalloway/op-go/internal/store"
)

type unlockableStore struct {
	fakeStore
	checks, unlocks     int
	unlockErr, checkErr error
	password            []byte
}

func (s *unlockableStore) CheckUnlock(context.Context) error { s.checks++; return s.checkErr }
func (s *unlockableStore) Unlock(_ context.Context, password []byte) error {
	s.unlocks++
	s.password = password
	if string(password) != "PASSWORD_SENTINEL" {
		return errors.New("unexpected password")
	}
	if s.unlockErr != nil {
		return s.unlockErr
	}
	s.err = nil
	return nil
}

func TestTerminalUnlock(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux terminal unlock")
	}
	for _, tc := range []struct {
		name, command, confirmation   string
		terminal, stdin, dry, present bool
		unlockErr, checkErr           error
		want, unlocks, passwords      int
	}{
		{name: "explicit", command: "unlock", terminal: true, unlocks: 1, passwords: 1},
		{name: "enrollment", command: "enroll", terminal: true, confirmation: "yes\n", unlocks: 1, passwords: 2},
		{name: "overwrite confirmed", command: "enroll", terminal: true, present: true, confirmation: "yes\nyes\n", unlocks: 1, passwords: 2},
		{name: "overwrite declined", command: "enroll", terminal: true, present: true, confirmation: "yes\nno\n", want: 2, unlocks: 1, passwords: 1},
		{name: "declined", command: "enroll", terminal: true, confirmation: "no\n", want: 11},
		{name: "wrong password", command: "enroll", terminal: true, confirmation: "yes\n", unlockErr: store.ErrLocked, want: 11, unlocks: 1, passwords: 1},
		{name: "timeout", command: "unlock", terminal: true, unlockErr: context.DeadlineExceeded, want: 20, unlocks: 1, passwords: 1},
		{name: "unsupported service", command: "unlock", terminal: true, checkErr: store.ErrUnavailable, want: 3},
		{name: "preflight timeout", command: "unlock", terminal: true, checkErr: context.DeadlineExceeded, want: 20},
		{name: "preflight denied", command: "unlock", terminal: true, checkErr: store.ErrDenied, want: 12},
		{name: "noninteractive unlock", command: "unlock", want: 2},
		{name: "piped enrollment", command: "enroll", stdin: true, want: 11},
		{name: "stdin flag even on tty", command: "enroll", stdin: true, terminal: true, want: 11},
		{name: "doctor", command: "doctor", terminal: true, want: 11},
		{name: "remove", command: "remove", terminal: true, want: 11},
		{name: "dry unlock", command: "unlock", dry: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &unlockableStore{fakeStore: fakeStore{err: store.ErrLocked, present: tc.present, token: "ORIGINAL"}, unlockErr: tc.unlockErr, checkErr: tc.checkErr}
			d := deps(&s.fakeStore)
			d.open = func(string, string) (store.Store, error) {
				if tc.dry {
					t.Fatal("dry run opened store")
				}
				return s, nil
			}
			d.input = strings.NewReader(tc.confirmation)
			d.terminal = tc.terminal
			passwords := 0
			d.password = func() ([]byte, error) {
				passwords++
				if passwords == 1 {
					return []byte("PASSWORD_SENTINEL"), nil
				}
				return []byte("TOKEN_SENTINEL"), nil
			}
			args := []string{tc.command, "--json"}
			if tc.stdin {
				args = append(args, "--stdin")
			}
			if tc.dry {
				args = append(args, "--dry-run")
			}
			code, out, stderr := invoke(t, args, d)
			if code != tc.want || s.unlocks != tc.unlocks || passwords != tc.passwords {
				t.Fatalf("code=%d unlocks=%d passwords=%d output=%s", code, s.unlocks, passwords, out+stderr)
			}
			jsonObject(t, out)
			for _, secret := range []string{"PASSWORD_SENTINEL", "TOKEN_SENTINEL"} {
				if strings.Contains(out+stderr, secret) {
					t.Fatal("secret disclosed")
				}
			}
			for _, b := range s.password {
				if b != 0 {
					t.Fatal("password buffer not cleared")
				}
			}
			if tc.command == "enroll" && code == 0 && s.token != "TOKEN_SENTINEL" {
				t.Fatal("token not enrolled after unlock")
			}
			if code != 0 && s.writes != 0 {
				t.Fatal("wrote after failure")
			}
			if code != 0 && s.token != "ORIGINAL" {
				t.Fatal("existing token changed after refusal")
			}
		})
	}
}

func TestUnlockedStoreDoesNotAskForPassword(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux terminal unlock")
	}
	s := &fakeStore{}
	d := deps(s)
	d.password = func() ([]byte, error) { t.Fatal("password requested"); return nil, nil }
	code, out, _ := invoke(t, []string{"unlock", "--json"}, d)
	if code != 0 || jsonObject(t, out)["ok"] != true || s.reads != 0 {
		t.Fatal("unlocked store should be a metadata-only success")
	}
}

func TestConfirmationDoesNotConsumeNextLine(t *testing.T) {
	r := strings.NewReader("yes\npassword\n")
	if !confirmed(r) || r.Len() != len("password\n") {
		t.Fatal("confirmation consumed password bytes")
	}
}
