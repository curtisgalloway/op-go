// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

// Package launch prepares a deterministic environment and replaces the launcher.
package launch

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/curtisgalloway/op-go/internal/store"
)

const maxEnvSize = 1024 * 1024

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Error contains only a safe, locally generated diagnostic.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string { return e.Message }

// Summary is safe to display: it contains names, never values or arguments.
type Summary struct {
	Executable    string   `json:"executable"`
	Keys          []string `json:"keys"`
	ReferenceKeys []string `json:"reference_keys"`
}

type entry struct {
	key, value string
	reference  bool
}

// Prepared holds an immutable launch plan. It must not be formatted or logged.
type Prepared struct {
	path      string
	command   []string
	entries   []entry
	inherited []string
}

func reserved(key string) bool {
	return key == "OP_SERVICE_ACCOUNT_TOKEN" || key == "OP_CONNECT_TOKEN" || strings.HasPrefix(key, "OP_SESSION_")
}

func parse(r io.Reader) ([]entry, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, maxEnvSize+1))
	scanner.Buffer(make([]byte, 4096), maxEnvSize+1)
	result := []entry{}
	seen := map[string]bool{}
	total := 0
	for line := 1; scanner.Scan(); line++ {
		raw := scanner.Text()
		total += len(raw) + 1
		if total > maxEnvSize {
			return nil, &Error{2, "environment file exceeds size limit"}
		}
		bad := func() ([]entry, error) {
			return nil, &Error{2, fmt.Sprintf("invalid environment entry at line %d", line)}
		}
		if strings.ContainsRune(raw, 0) {
			return bad()
		}
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimLeft(raw, " \t"), "#") {
			continue
		}
		key, value, ok := strings.Cut(raw, "=")
		if !ok || !namePattern.MatchString(key) || seen[key] || reserved(key) {
			return bad()
		}
		ref := strings.HasPrefix(value, "op://")
		if strings.Contains(value, "op://") && !ref {
			return bad()
		}
		if ref && !validReference(value) {
			return bad()
		}
		result = append(result, entry{key, value, ref})
		seen[key] = true
	}
	if scanner.Err() != nil {
		return nil, &Error{2, "cannot parse environment file"}
	}
	return result, nil
}

func validReference(value string) bool {
	parts := strings.Split(strings.TrimPrefix(value, "op://"), "/")
	if len(parts) != 3 && len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil || decoded == "" || strings.ContainsAny(decoded, "\x00\r\n") {
			return false
		}
	}
	return true
}

// Prepare parses without contacting a credential store or 1Password.
// The executable is selected using the original PATH, before file overrides.
func Prepare(envfile string, command []string) (*Prepared, error) {
	if len(command) == 0 || command[0] == "" {
		return nil, &Error{2, "a command is required after --"}
	}
	for _, arg := range command {
		if strings.ContainsRune(arg, 0) {
			return nil, &Error{2, "invalid command argument"}
		}
	}
	path, err := exec.LookPath(command[0])
	if err != nil {
		return nil, &Error{3, "command not found or not executable"}
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, &Error{3, "cannot locate command"}
	}
	var entries []entry
	if envfile != "" {
		f, err := os.OpenFile(envfile, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, &Error{3, "cannot open environment file"}
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return nil, &Error{2, "environment file must be a regular file"}
		}
		entries, err = parse(f)
		if err != nil {
			return nil, err
		}
	}
	return &Prepared{path, append([]string(nil), command...), entries, os.Environ()}, nil
}

// Summary returns only the executable path and environment key names.
func (p *Prepared) Summary() Summary {
	s := Summary{Executable: p.path, Keys: []string{}, ReferenceKeys: []string{}}
	for _, e := range p.entries {
		s.Keys = append(s.Keys, e.key)
		if e.reference {
			s.ReferenceKeys = append(s.ReferenceKeys, e.key)
		}
	}
	sort.Strings(s.Keys)
	sort.Strings(s.ReferenceKeys)
	return s
}

type resolver interface {
	Resolve(context.Context, string) (string, error)
}
type factory func(context.Context, string) (resolver, error)
type executor func(string, []string, []string) error

// Run resolves all values before replacing this process. No supervisor remains.
func (p *Prepared) Run(ctx context.Context, credentials store.Store, timeout time.Duration) error {
	return p.run(ctx, credentials, timeout, newSDKResolver, replace)
}

func (p *Prepared) run(ctx context.Context, credentials store.Store, timeout time.Duration, create factory, execute executor) error {
	for _, kv := range p.inherited {
		key, _, _ := strings.Cut(kv, "=")
		if key == "OP_SERVICE_ACCOUNT_TOKEN" {
			return &Error{12, "inherited service-account token detected; start from a clean environment"}
		}
	}
	if timeout <= 0 {
		return &Error{2, "timeout must be positive"}
	}
	values := make(map[string]string)
	for _, kv := range p.inherited {
		key, value, ok := strings.Cut(kv, "=")
		if ok && !reserved(key) {
			values[key] = value
		}
	}
	refs := false
	for _, e := range p.entries {
		refs = refs || e.reference
	}
	token := ""
	var resolved map[string]string
	if refs {
		if _, enabled := os.LookupEnv("EXTISM_ENABLE_WASI_OUTPUT"); enabled {
			return &Error{12, "SDK output override is forbidden; unset EXTISM_ENABLE_WASI_OUTPUT"}
		}
		var err error
		token, err = credentials.Read(ctx)
		if err != nil {
			return err
		}
		if token == "" || strings.ContainsAny(token, "\x00\r\n") {
			return &Error{3, "credential store returned an invalid token"}
		}
		networkCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		// The SDK's initial WebAssembly compilation does not accept a context.
		// Bound the entire operation here; the CLI exits on timeout, even if SDK
		// initialization has not returned. This goroutine never launches commands.
		type result struct {
			values map[string]string
			err    error
		}
		done := make(chan result, 1)
		go func() {
			defer func() {
				if recover() != nil {
					done <- result{nil, &Error{20, "1Password SDK failed; command was not launched"}}
				}
			}()
			r, err := create(networkCtx, token)
			if err != nil {
				done <- result{nil, safeSDKError(err, 10, "1Password authentication failed")}
				return
			}
			out := make(map[string]string)
			cache := make(map[string]string)
			for _, e := range p.entries {
				if !e.reference {
					continue
				}
				v, ok := cache[e.value]
				if !ok {
					v, err = r.Resolve(networkCtx, e.value)
					if err != nil {
						done <- result{nil, safeSDKError(err, 20, "secret resolution failed; SDK did not provide a supported error category")}
						return
					}
					cache[e.value] = v
				}
				if strings.ContainsRune(v, 0) {
					done <- result{nil, &Error{3, "resolved value cannot be used in an environment"}}
					return
				}
				out[e.key] = v
			}
			done <- result{out, nil}
		}()
		select {
		case <-networkCtx.Done():
			return &Error{20, "1Password operation timed out or was canceled; command was not launched"}
		case result := <-done:
			if result.err != nil {
				return result.err
			}
			resolved = result.values
		}
	}
	if err := ctx.Err(); err != nil {
		return &Error{20, "operation canceled; command was not launched"}
	}
	for _, e := range p.entries {
		if e.reference {
			values[e.key] = resolved[e.key]
		} else {
			values[e.key] = e.value
		}
	}
	env := make([]string, 0, len(values))
	for key, value := range values {
		if token != "" && strings.Contains(value, token) {
			return &Error{12, "service-account token would be exposed to the command"}
		}
		env = append(env, key+"="+value)
	}
	for _, arg := range p.command {
		if token != "" && strings.Contains(arg, token) {
			return &Error{12, "service-account token would be exposed to the command"}
		}
	}
	sort.Strings(env)
	if err := execute(p.path, p.command, env); err != nil {
		return &Error{3, "cannot execute command"}
	}
	return nil // Only test executors return successfully.
}

func safeSDKError(err error, code int, message string) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &Error{20, "1Password operation timed out or was canceled"}
	}
	return classifySDKError(err, code, message)
}
