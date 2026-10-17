// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	"encoding/json"
	"errors"
	onepassword "github.com/1password/onepassword-sdk-go"
	"strings"
	"testing"
	"time"
)

// Exercises the embedded SDK runtime offline: no authentication or store access.
func TestSDKReferenceValidationOffline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		for _, tc := range []struct {
			ref   string
			valid bool
		}{
			{"op://vault/item/field", true},
			{"op://Test Vault/Service Account Test/credential", true},
			{"op://Test Vault/Service Account: Test/credential", false},
			{"op://Test%20Vault/Service%20Account%3A%20Test/credential", false},
			{"op://vault/item/field?attribute=otp", true},
		} {
			err := onepassword.Secrets.ValidateSecretReference(ctx, tc.ref)
			if (err == nil) != tc.valid {
				done <- errors.New("SDK reference syntax disagrees with expected result")
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("SDK offline validation failed")
		}
	case <-ctx.Done():
		t.Fatal("SDK offline validation timed out")
	}
}
func TestSDKOutputOverrideRejectedBeforeTokenRead(t *testing.T) {
	t.Setenv("EXTISM_ENABLE_WASI_OUTPUT", "")
	p := &Prepared{entries: []entry{{"A", "op://v/i/f", true}}}
	s := &fakeStore{}
	err := p.run(context.Background(), s, time.Second, factoryOK, func(string, []string, []string) error { t.Fatal("executed"); return nil })
	if err == nil || s.reads != 0 {
		t.Fatal("unsafe output override accepted")
	}
}

func TestStructuredResolution(t *testing.T) {
	const ref = "op://fake-vault/fake-item/fake-field"
	type response = onepassword.Response[onepassword.ResolvedReference, onepassword.ResolveReferenceError]
	cases := []struct {
		name    string
		results map[string]response
		want    string
		code    int
	}{
		{"value", map[string]response{ref: {Content: &onepassword.ResolvedReference{Secret: "fake-secret"}}}, "fake-secret", 0},
		{"empty", map[string]response{ref: {Content: &onepassword.ResolvedReference{}}}, "", 0},
		{"missing response", nil, "", 20},
		{"wrong reference", map[string]response{"op://other/item/field": {Content: &onepassword.ResolvedReference{Secret: "fake-secret"}}}, "", 20},
		{"no outcome", map[string]response{ref: {}}, "", 20},
		{"contradictory", map[string]response{ref: {Content: &onepassword.ResolvedReference{Secret: "fake-secret"}, Error: &onepassword.ResolveReferenceError{Type: onepassword.ResolveReferenceErrorTypeVariantFieldNotFound}}}, "", 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			value, err := resolveSDKReference(context.Background(), ref, func(_ context.Context, refs []string) (onepassword.ResolveAllResponse, error) {
				calls++
				if len(refs) != 1 || refs[0] != ref {
					t.Fatal("incorrect request")
				}
				return onepassword.ResolveAllResponse{IndividualResponses: tc.results}, nil
			})
			if calls != 1 || value != tc.want {
				t.Fatal("incorrect resolution or retry")
			}
			if tc.code == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var failure *Error
			if !errors.As(safeSDKError(err, 20, "failed"), &failure) || failure.Code != tc.code {
				t.Fatal("incorrect error status")
			}
		})
	}
}

func TestReferenceErrorCategoriesAreSanitized(t *testing.T) {
	cases := []struct {
		kind    onepassword.ResolveReferenceErrorTypes
		code    int
		message string
	}{
		{onepassword.ResolveReferenceErrorTypeVariantParsing, 2, "syntax"},
		{onepassword.ResolveReferenceErrorTypeVariantVaultNotFound, 3, "vault not found"},
		{onepassword.ResolveReferenceErrorTypeVariantItemNotFound, 3, "item not found"},
		{onepassword.ResolveReferenceErrorTypeVariantFieldNotFound, 3, "field not found"},
		{onepassword.ResolveReferenceErrorTypeVariantNoMatchingSections, 3, "section not found"},
		{onepassword.ResolveReferenceErrorTypeVariantTooManyVaults, 3, "vault name is ambiguous"},
		{onepassword.ResolveReferenceErrorTypeVariantTooManyItems, 3, "item name is ambiguous"},
		{onepassword.ResolveReferenceErrorTypeVariantTooManyMatchingFields, 3, "field is ambiguous"},
		{onepassword.ResolveReferenceErrorTypeVariantIncompatibleTOTPQueryParameterField, 3, "incompatible"},
		{onepassword.ResolveReferenceErrorTypeVariantIncompatibleSSHKeyQueryParameterField, 3, "incompatible"},
		{onepassword.ResolveReferenceErrorTypeVariantUnsupportedFileFormat, 3, "incompatible"},
		{onepassword.ResolveReferenceErrorTypeVariantOther, 20, "supported error category"},
		{"fake-private-unknown-type", 20, "supported error category"},
	}
	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			// The SDK's error payload may contain identifiers or secrets. Never render it.
			raw, _ := json.Marshal(map[string]string{"type": string(tc.kind), "message": "fake-private-payload"})
			var sdkError onepassword.ResolveReferenceError
			if err := json.Unmarshal(raw, &sdkError); err != nil {
				t.Fatal(err)
			}
			_, err := resolveSDKReference(context.Background(), "op://fake/item/field", func(context.Context, []string) (onepassword.ResolveAllResponse, error) {
				return onepassword.ResolveAllResponse{IndividualResponses: map[string]onepassword.Response[onepassword.ResolvedReference, onepassword.ResolveReferenceError]{"op://fake/item/field": {Error: &sdkError}}}, nil
			})
			var failure *Error
			if !errors.As(safeSDKError(err, 20, "failed"), &failure) || failure.Code != tc.code || !strings.Contains(failure.Error(), tc.message) || strings.Contains(failure.Error(), "fake-private") {
				t.Fatal("incorrect or unsafe diagnostic")
			}
		})
	}
}

func TestResolutionFailuresNeverExecuteOrRetry(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{errors.New("fake-private-payload permission denied 429"), 20},
		{&onepassword.RateLimitExceededError{}, 23},
		{&onepassword.DesktopSessionExpiredError{}, 10},
		{context.DeadlineExceeded, 20},
		{&sdkReferenceError{kind: onepassword.ResolveReferenceErrorTypeVariantFieldNotFound}, 3},
	} {
		calls := 0
		p := &Prepared{entries: []entry{{"A", "op://fake/item/field", true}, {"B", "op://fake/item/other", true}}}
		err := p.run(context.Background(), &fakeStore{}, time.Second, func(context.Context, string) (resolver, error) {
			return resolverFunc(func(context.Context, string) (string, error) { calls++; return "fake-partial-secret", tc.err }), nil
		}, func(string, []string, []string) error { t.Fatal("executed after failure"); return nil })
		var failure *Error
		if calls != 1 || !errors.As(err, &failure) || failure.Code != tc.code || strings.Contains(err.Error(), "fake-") {
			t.Fatal("unsafe failure handling")
		}
	}
}

type resolverFunc func(context.Context, string) (string, error)

func (f resolverFunc) Resolve(ctx context.Context, ref string) (string, error) { return f(ctx, ref) }
