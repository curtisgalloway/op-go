// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	onepassword "github.com/1password/onepassword-sdk-go"
	"testing"
	"time"
)

// Exercises the embedded SDK runtime offline: no authentication or store access.
func TestSDKReferenceValidationOffline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- onepassword.Secrets.ValidateSecretReference(ctx, "op://vault/item/field") }()
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
