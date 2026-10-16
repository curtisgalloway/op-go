// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

// Package cli implements the credential-safe command interface.
package cli

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/curtisgalloway/op-go/internal/launch"
	"github.com/curtisgalloway/op-go/internal/store"
	"golang.org/x/term"
)

//go:embed SKILL.md
var skill string

var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

const help = `op-go — launch commands with 1Password secrets

Usage:
  op-go run --env-file PATH [options] -- command args
  op-go dry-run --env-file PATH [options] [--json] -- command args
  op-go enroll [--stdin] [--yes] [--dry-run] [--json] [options]
  op-go remove [--yes] [--dry-run] [--json] [options]
  op-go doctor [--json] [options]
  op-go --help | --version | --skill

Options:
  --backend keychain|secret-service|file  (default: platform credential store)
  --token-file PATH                      (required for read-only file backend)
  --timeout DURATION                     (run/dry-run; default 30s)

Enrollment reads hidden terminal input unless --stdin is explicit.
Overwrite/removal require --yes or terminal confirmation; stdin tokens cannot
provide confirmation. Stores must already be unlocked. Doctor is offline and
reads metadata only. Dry-run does not retrieve or resolve secrets or print values.
Run rejects --json; after exec the target owns stdout, stderr, and exit status.
Application secrets enter the target environment and may be visible in ps.
Start credential operations without inherited OP_SERVICE_ACCOUNT_TOKEN.

Launcher exit status:
  0 success; 2 invalid arguments/consent; 3 missing execution precondition
  10 authentication failed; 11 store locked; 12 credential access policy denied
  20 operation failed; 22 credential mutation interrupted or response lost (outcome unknown)
  23 1Password rate limit reached
`

type dependencies struct {
	open     func(string, string) (store.Store, error)
	lookup   func(string) (string, bool)
	input    io.Reader
	terminal bool
	password func() ([]byte, error)
}

// Run executes the CLI. Successful run replaces this process with the target.
func Run(args []string, stdout, stderr io.Writer) int {
	return run(args, stdout, stderr, dependencies{
		open: store.Open, lookup: os.LookupEnv, input: os.Stdin,
		terminal: term.IsTerminal(int(os.Stdin.Fd())),
		password: func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) },
	})
}

type options struct {
	backend, tokenFile, envFile string
	timeout                     time.Duration
	json, dry, yes, stdin       bool
}

func run(args []string, stdout, stderr io.Writer, d dependencies) int {
	if len(args) == 0 || len(args) == 1 && (args[0] == "--help" || args[0] == "help" || args[0] == "-h") {
		fmt.Fprint(stdout, help)
		return 0
	}
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintf(stdout, "op-go %s (%s, %s)\n", Version, Commit, Date)
		return 0
	}
	if len(args) == 1 && args[0] == "--skill" {
		fmt.Fprint(stdout, strings.ReplaceAll(skill, "{{VERSION}}", Version+" ("+Commit+", "+Date+")"))
		return 0
	}
	command := args[0]
	management := command == "enroll" || command == "remove" || command == "doctor" || command == "dry-run"
	wantsJSON := false
	for _, a := range args[1:] {
		if a == "--" {
			break
		}
		if a == "--json" || a == "--json=true" {
			wantsJSON = true
		}
	}
	fail := func(code int, message string) int {
		if management && wantsJSON {
			_ = json.NewEncoder(stdout).Encode(map[string]any{"ok": false, "error": message})
		} else {
			fmt.Fprintln(stderr, message)
		}
		return code
	}
	if !management && command != "run" {
		return fail(2, "invalid command; use op-go --help")
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := options{backend: "secret-service"}
	if runtime.GOOS == "darwin" {
		o.backend = "keychain"
	}
	fs.StringVar(&o.backend, "backend", o.backend, "")
	fs.StringVar(&o.tokenFile, "token-file", "", "")
	if management {
		fs.BoolVar(&o.json, "json", false, "")
	}
	if command == "run" || command == "dry-run" {
		fs.StringVar(&o.envFile, "env-file", "", "")
		fs.DurationVar(&o.timeout, "timeout", 30*time.Second, "")
	}
	if command == "enroll" || command == "remove" {
		fs.BoolVar(&o.yes, "yes", false, "")
		fs.BoolVar(&o.dry, "dry-run", false, "")
	}
	if command == "enroll" {
		fs.BoolVar(&o.stdin, "stdin", false, "")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if wantsJSON {
				return fail(2, "--help cannot be combined with --json")
			}
			fmt.Fprint(stdout, help)
			return 0
		}
		return fail(2, "invalid options; use op-go --help")
	}
	wantsJSON = o.json
	if o.backend != "keychain" && o.backend != "secret-service" && o.backend != "file" {
		return fail(2, "unsupported credential backend")
	}
	if (o.backend == "file") != (o.tokenFile != "") {
		return fail(2, "--token-file is required only with --backend file")
	}
	if command != "run" && command != "dry-run" && fs.NArg() != 0 {
		return fail(2, "unexpected positional arguments")
	}
	if _, exists := d.lookup("OP_SERVICE_ACCOUNT_TOKEN"); exists {
		return fail(12, "inherited OP_SERVICE_ACCOUNT_TOKEN is forbidden; start from a clean environment (unsetting it cannot undo prior exposure)")
	}
	emit := func(v any, human string) int {
		if o.json {
			_ = json.NewEncoder(stdout).Encode(v)
		} else {
			fmt.Fprintln(stdout, human)
		}
		return 0
	}
	if command == "run" || command == "dry-run" {
		if o.envFile == "" || o.timeout <= 0 || fs.NArg() == 0 {
			return fail(2, "provide --env-file, positive --timeout, and -- command")
		}
		separator := false
		for i, a := range args[1:] {
			if a == "--" {
				separator = fs.NArg() == len(args)-i-2
				break
			}
		}
		if !separator {
			return fail(2, "separate the target command with --")
		}
		p, err := launch.Prepare(o.envFile, fs.Args())
		if err != nil {
			code, msg := launchFailure(err)
			return fail(code, msg)
		}
		if command == "dry-run" {
			s := p.Summary()
			return emit(map[string]any{"ok": true, "operation": "run", "backend": o.backend, "keys": s.Keys, "reference_keys": s.ReferenceKeys}, "dry-run: run; backend="+o.backend+"; keys="+strings.Join(s.Keys, ","))
		}
		s, err := d.open(o.backend, o.tokenFile)
		if err != nil {
			code, msg := storeFailure(err)
			return fail(code, msg)
		}
		if err = p.Run(context.Background(), s, o.timeout); err != nil {
			code, msg := launchFailure(err)
			return fail(code, msg)
		}
		return 0
	}
	if (command == "enroll" || command == "remove") && o.backend == "file" {
		return fail(2, "file backend is read-only; provision or remove it externally")
	}
	if o.dry {
		return emit(map[string]any{"ok": true, "dry_run": true, "operation": command, "backend": o.backend}, "dry-run: "+command+"; backend="+o.backend)
	}
	s, err := d.open(o.backend, o.tokenFile)
	if err != nil {
		code, msg := storeFailure(err)
		return fail(code, msg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	present, err := s.Status(ctx)
	cancel()
	if err != nil {
		code, msg := storeFailure(err)
		return fail(code, msg)
	}
	if command == "doctor" {
		if !present {
			return fail(3, "token not enrolled; enroll a token in the selected store")
		}
		return emit(map[string]any{"ok": true, "backend": o.backend, "enrolled": true, "online_check": false}, "credential metadata present; token validity not checked")
	}
	if (command == "remove" || present) && !o.yes {
		if !d.terminal || o.stdin {
			return fail(2, "explicit --yes required without a confirmation terminal; token input cannot provide consent")
		}
		fmt.Fprint(stderr, "Confirm credential "+command+" (type yes): ")
		answer, err := bufio.NewReader(d.input).ReadString('\n')
		if err != nil || strings.TrimSpace(answer) != "yes" {
			return fail(2, "credential operation not confirmed")
		}
	}
	if command == "remove" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Delete(ctx); err != nil {
			code, msg := mutationFailure(err)
			return fail(code, msg)
		}
		return emit(map[string]any{"ok": true, "operation": "remove", "backend": o.backend}, "credential removed")
	}
	if !o.stdin && !d.terminal {
		return fail(2, "enrollment requires a terminal or explicit --stdin")
	}
	var data []byte
	if o.stdin {
		data, err = io.ReadAll(io.LimitReader(d.input, 65537))
	} else {
		fmt.Fprint(stderr, "Service-account token: ")
		data, err = d.password()
		fmt.Fprintln(stderr)
	}
	if err != nil {
		return fail(20, "could not read credential input")
	}
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()
	token, valid := validToken(data)
	if !valid {
		return fail(2, "token must be nonempty valid UTF-8, at most 64 KiB, and contain no control characters")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = s.Write(ctx, token, present); err != nil {
		code, msg := mutationFailure(err)
		return fail(code, msg)
	}
	return emit(map[string]any{"ok": true, "operation": "enroll", "backend": o.backend, "online_check": false}, "credential enrolled; token validity not checked")
}

func validToken(data []byte) (string, bool) {
	token, err := store.NormalizeToken(string(data))
	return token, err == nil
}

func storeFailure(err error) (int, string) {
	switch {
	case errors.Is(err, store.ErrUnavailable):
		return 3, "credential store unavailable; select an available backend"
	case errors.Is(err, store.ErrLocked):
		return 11, "credential store locked; unlock it separately"
	case errors.Is(err, store.ErrDenied):
		return 12, "credential store access denied"
	case errors.Is(err, store.ErrNotFound):
		return 3, "token not enrolled"
	case errors.Is(err, store.ErrExists):
		return 2, "credential already exists; rerun with explicit overwrite consent"
	case errors.Is(err, store.ErrInvalidFile):
		return 12, "credential file must be an owned regular file without symlinks or group/other access"
	default:
		return 20, "credential operation failed"
	}
}

func launchFailure(err error) (int, string) {
	var e *launch.Error
	if errors.As(err, &e) {
		return e.Code, e.Message
	}
	for _, sentinel := range []error{store.ErrUnavailable, store.ErrLocked, store.ErrDenied, store.ErrNotFound, store.ErrExists, store.ErrInvalidFile} {
		if errors.Is(err, sentinel) {
			return storeFailure(err)
		}
	}
	return 20, "secret resolution or launch failed"
}

func mutationFailure(err error) (int, string) {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, store.ErrOutcomeUnknown) {
		return 22, "credential operation outcome unknown; inspect metadata before retrying"
	}
	return storeFailure(err)
}
