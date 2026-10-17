// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
)

func requireLaunchError(t *testing.T, err error, code int) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != code {
		t.Fatalf("expected status %d, got %v", code, err)
	}
	for _, sentinel := range []string{"dummy-service-token", "fake-secret", "private-payload"} {
		if strings.Contains(err.Error(), sentinel) {
			t.Fatal("diagnostic disclosed a sentinel")
		}
	}
}

func TestCanceledLaunchDoesNotReadCredentials(t *testing.T) {
	for _, refs := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		p := &Prepared{entries: []entry{{"A", "literal", false}}}
		if refs {
			p.entries = []entry{{"A", "op://v/i/f", true}}
		}
		s := &fakeStore{}
		err := p.run(ctx, s, time.Second, func(context.Context, string) (resolver, error) {
			t.Error("created SDK after cancellation")
			return fakeResolver{}, nil
		}, func(string, []string, []string) error { t.Error("executed after cancellation"); return nil })
		requireLaunchError(t, err, 20)
		if s.reads != 0 {
			t.Fatal("read credentials after cancellation")
		}
	}
}

func TestResolutionTimeoutAndCancellation(t *testing.T) {
	for _, mode := range []string{"deadline", "parent cancellation", "late success"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				started := make(chan struct{})
				release := make(chan struct{})
				finished := make(chan struct{})
				result := make(chan error, 1)
				p := &Prepared{entries: []entry{{"A", "op://v/i/f", true}, {"B", "op://v/i/other", true}}}
				calls := 0
				go func() {
					result <- p.run(ctx, &fakeStore{}, time.Second, func(context.Context, string) (resolver, error) {
						return resolverFunc(func(callCtx context.Context, _ string) (string, error) {
							calls++
							if calls != 1 {
								return "fake-secret", nil
							}
							close(started)
							if mode == "late success" {
								<-release
								close(finished)
								return "fake-secret", nil
							}
							<-callCtx.Done()
							close(finished)
							return "", callCtx.Err()
						}), nil
					}, func(string, []string, []string) error { t.Error("executed after cancellation/timeout"); return nil })
				}()
				<-started
				if mode == "parent cancellation" {
					cancel()
				} else {
					time.Sleep(2 * time.Second)
				}
				requireLaunchError(t, <-result, 20)
				if mode == "late success" {
					close(release)
				}
				<-finished
				synctest.Wait()
				if calls != 1 {
					t.Fatalf("resolved additional references after cancellation: %d", calls)
				}
			})
		})
	}
}

func TestLaunchRefusesUnsafeSecretExposure(t *testing.T) {
	for _, tc := range []struct {
		name, value        string
		inherited, command []string
		code               int
	}{
		{name: "NUL", value: "fake-secret\x00suffix", code: 3},
		{name: "resolved token", value: "prefix-dummy-service-token-suffix", code: 12},
		{name: "inherited token copy", value: "fake-secret", inherited: []string{"COPY=prefix-dummy-service-token-suffix"}, code: 12},
		{name: "argument token copy", value: "fake-secret", command: []string{"program", "prefix-dummy-service-token-suffix"}, code: 12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Prepared{entries: []entry{{"A", "op://v/i/f", true}}, inherited: tc.inherited, command: tc.command}
			err := p.run(context.Background(), &fakeStore{}, time.Second, func(context.Context, string) (resolver, error) {
				return resolverFunc(func(context.Context, string) (string, error) { return tc.value, nil }), nil
			}, func(string, []string, []string) error { t.Error("unsafe value reached child"); return nil })
			requireLaunchError(t, err, tc.code)
		})
	}
}

func TestPartialResolutionFailureNeverExecutes(t *testing.T) {
	p := &Prepared{entries: []entry{{"A", "op://v/i/good", true}, {"B", "op://v/i/bad", true}, {"C", "op://v/i/unreached", true}}}
	calls := 0
	err := p.run(context.Background(), &fakeStore{}, time.Second, func(context.Context, string) (resolver, error) {
		return resolverFunc(func(ctx context.Context, ref string) (string, error) {
			calls++
			return (fakeResolver{}).Resolve(ctx, ref)
		}), nil
	}, func(string, []string, []string) error {
		t.Error("executed after partial resolution failure")
		return nil
	})
	requireLaunchError(t, err, 20)
	if calls != 2 {
		t.Fatalf("expected exactly two reads, got %d", calls)
	}
}

func TestInitializationErrorsAreSanitized(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{errors.New("dummy-service-token private-payload"), 10},
		{&onepassword.RateLimitExceededError{}, 23},
	} {
		calls := 0
		p := &Prepared{entries: []entry{{"A", "op://v/i/f", true}}}
		err := p.run(context.Background(), &fakeStore{}, time.Second, func(context.Context, string) (resolver, error) { calls++; return nil, tc.err }, func(string, []string, []string) error { t.Error("executed after initialization failure"); return nil })
		requireLaunchError(t, err, tc.code)
		if calls != 1 {
			t.Fatal("retried initialization")
		}
	}
}

func TestEmptyResolutionOverridesAndCaches(t *testing.T) {
	p := &Prepared{entries: []entry{{"A", "op://v/i/f", true}, {"B", "op://v/i/f", true}}, inherited: []string{"A=old", "B=old", "BASE=keep"}}
	calls, executions := 0, 0
	err := p.run(context.Background(), &fakeStore{}, time.Second, func(context.Context, string) (resolver, error) {
		return resolverFunc(func(context.Context, string) (string, error) { calls++; return "", nil }), nil
	}, func(_ string, _ []string, env []string) error {
		executions++
		if !reflect.DeepEqual(env, []string{"A=", "B=", "BASE=keep"}) {
			t.Error("empty values did not override inherited values")
		}
		return nil
	})
	if err != nil || calls != 1 || executions != 1 {
		t.Fatalf("error=%v reads=%d executions=%d", err, calls, executions)
	}
}
