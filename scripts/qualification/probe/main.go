// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

// An opt-in SDK-only probe. Token export is exclusively a caller-supplied pipe,
// used by the in-memory process observer. No token is written to standard output.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"runtime"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/curtisgalloway/op-go/internal/store"
	"github.com/curtisgalloway/op-go/scripts/qualification/checkpoint"
)

func main() {
	if worker, code := store.Worker(os.Args[1:]); worker {
		os.Exit(code)
	}
	export := flag.Int("observer-fd", -1, "deliver token only to supplied private pipe")
	refFile := flag.String("reference-file", "", "nonsecret reference file")
	timeout := flag.Duration("timeout", 30*time.Second, "SDK deadline")
	flag.Parse()
	if _, exists := os.LookupEnv("OP_SERVICE_ACCOUNT_TOKEN"); exists {
		os.Exit(12)
	}
	backend := "secret-service"
	if runtime.GOOS == "darwin" {
		backend = "keychain"
	}
	s, err := store.Open(backend, "")
	if err != nil {
		os.Exit(3)
	}
	token, err := s.Read(context.Background())
	if err != nil {
		os.Exit(3)
	}
	if *export >= 0 {
		if *export < 3 {
			os.Exit(2)
		}
		f := os.NewFile(uintptr(*export), "observer")
		if f == nil {
			os.Exit(2)
		}
		defer f.Close()
		info, e := f.Stat()
		if e != nil || info.Mode()&os.ModeNamedPipe == 0 {
			os.Exit(2)
		}
		if _, e = f.Write([]byte(token)); e != nil {
			os.Exit(20)
		}
		return
	}
	ref, err := os.ReadFile(*refFile)
	if err != nil {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	phase := "initialization"
	start := time.Now()
	client, err := onepassword.NewClient(ctx, onepassword.WithServiceAccountToken(token), onepassword.WithIntegrationInfo("op-go-qualification", "0.1.0"))
	if err == nil {
		phase = "resolution"
		checkpoint.Hit("sdk-initialized")
		var response onepassword.ResolveAllResponse
		response, err = client.Secrets().ResolveAll(ctx, []string{string(ref)})
		if err == nil {
			v, ok := response.IndividualResponses[string(ref)]
			if !ok || v.Content == nil || v.Error != nil || v.Content.Secret != "op-go-test-value" {
				err = errors.New("unexpected result")
			}
		}
	}
	code, category := 0, "success"
	if err != nil {
		code, category = 20, "unclassified"
		var rate *onepassword.RateLimitExceededError
		if errors.As(err, &rate) {
			code, category = 23, "rate-limit"
		} else if ctx.Err() != nil {
			category = "timeout"
		} else if phase == "initialization" {
			code, category = 10, "authentication-or-initialization"
		}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": phase, "status": code, "category": category, "seconds": time.Since(start).Seconds()})
	os.Exit(code)
}
