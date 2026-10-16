// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

// Command op-go is the entry point for the credential-safe command launcher.
package main

import (
	"github.com/curtisgalloway/op-go/internal/cli"
	"github.com/curtisgalloway/op-go/internal/store"
	"os"
)

func main() {
	if handled, code := store.Worker(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
