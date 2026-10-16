// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/curtisgalloway/op-go/internal/store"
)

type fakeStore struct {
	present                          bool
	reads, writes, deletes, statuses int
	token                            string
	overwrite                        bool
	err                              error
}

func (s *fakeStore) Status(context.Context) (bool, error) { s.statuses++; return s.present, s.err }
func (s *fakeStore) Read(context.Context) (string, error) { s.reads++; return "DO_NOT_PRINT", s.err }
func (s *fakeStore) Write(_ context.Context, token string, overwrite bool) error {
	s.writes++
	s.token = token
	s.overwrite = overwrite
	return s.err
}
func (s *fakeStore) Delete(context.Context) error { s.deletes++; return s.err }
func deps(s *fakeStore) dependencies {
	return dependencies{open: func(string, string) (store.Store, error) { return s, nil }, lookup: func(string) (string, bool) { return "", false }, input: strings.NewReader("fake-token\n")}
}
func invoke(t *testing.T, args []string, d dependencies) (int, string, string) {
	t.Helper()
	var out, err bytes.Buffer
	code := run(args, &out, &err, d)
	return code, out.String(), err.String()
}
func jsonObject(t *testing.T, s string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("invalid JSON: %q", s)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		t.Fatal("multiple JSON documents")
	}
	return v
}

func TestMetadataAndDryRunsNeverRead(t *testing.T) {
	for _, args := range [][]string{{"doctor", "--json"}, {"enroll", "--dry-run", "--json"}, {"remove", "--dry-run", "--json"}} {
		s := &fakeStore{present: true}
		d := deps(s)
		if args[0] != "doctor" {
			d.open = func(string, string) (store.Store, error) { t.Fatal("dry-run opened store"); return nil, nil }
		}
		code, out, _ := invoke(t, args, d)
		if code != 0 {
			t.Fatalf("%v: %d", args, code)
		}
		jsonObject(t, out)
		if s.reads+s.writes+s.deletes != 0 {
			t.Fatal("credential value access")
		}
	}
}
func TestLaunchDryRunDoesNotAccessCredentialsOrPrintValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.env")
	if err := os.WriteFile(path, []byte("TOKEN=op://vault/item/field\nLITERAL=SENTINEL_SECRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	d := deps(&fakeStore{})
	d.open = func(string, string) (store.Store, error) { t.Fatal("opened credentials"); return nil, nil }
	code, out, stderr := invoke(t, []string{"dry-run", "--env-file", path, "--json", "--", "/bin/sh", "SENTINEL_ARG"}, d)
	if code != 0 {
		t.Fatalf("%d: %s", code, stderr)
	}
	jsonObject(t, out)
	for _, forbidden := range []string{"SENTINEL_SECRET", "SENTINEL_ARG", "op://vault"} {
		if strings.Contains(out+stderr, forbidden) {
			t.Fatal("disclosed value")
		}
	}
}
func TestInheritedTokenRejectedEvenEmpty(t *testing.T) {
	for _, args := range [][]string{{"doctor", "--json"}, {"enroll", "--stdin"}, {"remove", "--yes"}, {"enroll", "--dry-run"}} {
		d := deps(&fakeStore{})
		d.lookup = func(string) (string, bool) { return "", true }
		d.open = func(string, string) (store.Store, error) { t.Fatal("opened store"); return nil, nil }
		code, _, _ := invoke(t, args, d)
		if code != 12 {
			t.Fatalf("%v: %d", args, code)
		}
	}
}
func TestEnrollmentConsentAndInput(t *testing.T) {
	for _, tc := range []struct {
		name                string
		present, stdin, yes bool
		want                int
	}{{"noninteractive", false, false, false, 2}, {"new stdin", false, true, false, 0}, {"overwrite without consent", true, true, false, 2}, {"overwrite consent", true, true, true, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			s := &fakeStore{present: tc.present}
			d := deps(s)
			args := []string{"enroll", "--json"}
			if tc.stdin {
				args = append(args, "--stdin")
			}
			if tc.yes {
				args = append(args, "--yes")
			}
			code, out, stderr := invoke(t, args, d)
			if code != tc.want {
				t.Fatalf("%d: %s", code, out+stderr)
			}
			jsonObject(t, out)
			if code == 0 {
				if s.writes != 1 || s.token != "fake-token" || s.overwrite != tc.present {
					t.Fatalf("write: %+v", s)
				}
			} else if s.writes != 0 {
				t.Fatal("unexpected write")
			}
			if strings.Contains(out+stderr, "fake-token") {
				t.Fatal("token disclosed")
			}
		})
	}
}
func TestRawErrorsAndFlagsAreRedacted(t *testing.T) {
	for _, args := range [][]string{{"doctor", "--json"}, {"doctor", "--json", "--SECRET_VALUE"}, {"run", "--json"}} {
		s := &fakeStore{err: errors.New("SECRET_VALUE")}
		code, out, stderr := invoke(t, args, deps(s))
		if code == 0 {
			t.Fatal("expected failure")
		}
		if strings.Contains(out+stderr, "SECRET_VALUE") {
			t.Fatal("raw error disclosed")
		}
		if args[0] == "doctor" {
			jsonObject(t, out)
		}
	}
}
func TestTokenValidation(t *testing.T) {
	for _, tc := range []struct {
		input string
		valid bool
	}{{"", false}, {"value", true}, {"value\n", true}, {"value\r\n", true}, {"value\r", false}, {"value\n\n", false}, {"value\x00", false}, {"value\t", false}, {"value\xff", false}, {strings.Repeat("a", 65537), false}} {
		_, valid := validToken([]byte(tc.input))
		if valid != tc.valid {
			t.Errorf("length %d: valid %v", len(tc.input), valid)
		}
	}
}
func TestRemovalConsentAndFileReadOnly(t *testing.T) {
	for _, args := range [][]string{{"remove", "--json"}, {"remove", "--backend", "file", "--token-file", "unused", "--yes", "--json"}, {"enroll", "--backend", "file", "--token-file", "unused", "--dry-run", "--json"}} {
		s := &fakeStore{present: true}
		code, out, _ := invoke(t, args, deps(s))
		if code != 2 {
			t.Fatalf("%v: %d", args, code)
		}
		jsonObject(t, out)
		if s.deletes+s.writes != 0 {
			t.Fatal("mutated store")
		}
	}
	s := &fakeStore{present: true}
	code, out, _ := invoke(t, []string{"remove", "--yes", "--json"}, deps(s))
	if code != 0 || s.deletes != 1 {
		t.Fatal("remove failed")
	}
	jsonObject(t, out)
}

func TestCommandRequiresActualSeparator(t *testing.T) {
	for _, args := range [][]string{{"dry-run", "--env-file", "unused", "/bin/sh"}, {"dry-run", "--env-file", "unused", "/bin/sh", "--"}} {
		code, _, _ := invoke(t, args, deps(&fakeStore{}))
		if code != 2 {
			t.Fatalf("invalid separator accepted: %v (%d)", args, code)
		}
	}
}

func TestLaunchStoreErrorsKeepExitCodes(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{{store.ErrLocked, 11}, {store.ErrDenied, 12}, {store.ErrNotFound, 3}, {store.ErrUnavailable, 3}, {store.ErrInvalidFile, 12}, {store.ErrExists, 2}} {
		code, msg := launchFailure(errors.Join(errors.New("SECRET_VALUE"), tc.err))
		if code != tc.code || strings.Contains(msg, "SECRET_VALUE") {
			t.Fatalf("wrong classification: %d %s", code, msg)
		}
	}
}

func TestMutationInterruptionOutcomeUnknown(t *testing.T) {
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, store.ErrOutcomeUnknown} {
		code, msg := mutationFailure(err)
		if code != 22 || !strings.Contains(msg, "outcome unknown") {
			t.Fatalf("%d %s", code, msg)
		}
		code, _ = storeFailure(err)
		if code != 20 {
			t.Fatalf("read interruption: %d", code)
		}
	}
}

func TestJSONHelpCombinationRejected(t *testing.T) {
	for _, command := range []string{"run", "doctor", "enroll", "remove", "dry-run"} {
		for _, flags := range [][]string{{"--help", "--json"}, {"--json", "--help"}} {
			args := append([]string{command}, flags...)
			code, out, stderr := invoke(t, args, deps(&fakeStore{}))
			if code != 2 {
				t.Fatalf("%v: %d %s %s", args, code, out, stderr)
			}
			if command != "run" {
				v := jsonObject(t, out)
				if v["ok"] != false {
					t.Fatal("expected JSON error")
				}
			} else if out != "" {
				t.Fatal("run must not emit help on stdout")
			}
		}
	}
}
