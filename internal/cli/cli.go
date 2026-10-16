// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

// Package cli implements the bootstrap command interface.
package cli

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

//go:embed SKILL.md
var skill string

// Build metadata can be set with linker flags.
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

const help = `op-go — launch commands with 1Password secrets

This build is a scaffold. Credential storage and command launching are not implemented.

Usage:
  op-go --help
  op-go --version
  op-go --skill
  op-go doctor [--json]

Exit status (launcher):
  0  informational command succeeded
  2  invalid arguments
  3  required functionality or configuration unavailable

Doctor performs no credential access and reports the scaffold as not ready.
`

// Run executes an informational command without accessing credentials.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (len(args) == 1 && args[0] == "--help") {
		fmt.Fprint(stdout, help)
		return 0
	}
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintf(stdout, "op-go %s (%s, %s)\n", Version, Commit, Date)
		return 0
	}
	if len(args) == 1 && args[0] == "--skill" {
		fmt.Fprint(stdout, strings.ReplaceAll(skill, "{{VERSION}}", Version+" ("+Commit+", "+Date+")"))
		return 0
	}
	if args[0] == "doctor" && (len(args) == 1 || (len(args) == 2 && args[1] == "--json")) {
		if len(args) == 2 {
			_ = json.NewEncoder(stdout).Encode(struct {
				Ready  bool   `json:"ready"`
				Reason string `json:"reason"`
			}{false, "credential storage and command launching are not implemented"})
		} else {
			fmt.Fprintln(stderr, "not ready: credential storage and command launching are not implemented")
		}
		return 3
	}
	fmt.Fprintln(stderr, "invalid arguments; use op-go --help")
	return 2
}
