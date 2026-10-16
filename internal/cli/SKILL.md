---
name: op-go
description: Launch commands with 1Password secrets while keeping the service-account token out of arguments and environment variables.
---

<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# op-go {{VERSION}}

**Terms:** SDK means the official 1Password software library. A service-account
token authenticates to selected vaults. Keychain and Secret Service are operating
system credential stores. See the repository GLOSSARY.md for additional terms.

## Invocation

```sh
op-go --help
op-go --version
op-go --skill
op-go doctor --json
op-go enroll
op-go enroll --stdin --yes
op-go remove --yes
op-go dry-run --env-file .env --json -- program
op-go run --env-file .env -- program arguments
```

Credential options: `--backend keychain|secret-service|file` and `--token-file PATH`.
The default backend is Keychain on macOS and Secret Service on Linux. The file
backend requires a token file and is read-only: provision and remove it externally.
There is no automatic plaintext fallback. Run and standalone dry-run accept
`--timeout DURATION` (default `30s`, positive), bounding SDK operations.
Credential store operations have a separate five-second bound.

Enrollment accepts hidden terminal input, or explicit `--stdin` with at most
64 KiB of input. A single trailing newline is accepted; other control characters
and invalid UTF-8 are rejected. Tokens cannot be passed as flags or read from environment variables.
An existing token requires `--yes` or terminal confirmation to overwrite. Removal
has the same consent requirement. Stdin token input cannot double as consent.
The store must already be unlocked; unlock it separately. Enrollment does not
validate the token online.

Enrollment and removal accept `--dry-run`. They report the operation and backend
without opening the store. Standalone dry-run validates the environment file and
executable and reports key names, never values, references, or command arguments.
Doctor reads credential metadata only: no token retrieval or network access.

## Environment files

One explicit `--env-file` is required. Use ASCII shell-style names and `KEY=value`
entries, blank lines, and full-line comments. Values are literal; quotes, `$`,
backticks, and inline `#` have no special meaning. A complete value beginning with
`op://` is resolved. No expansion, embedded references, multiline values, duplicate
keys, or `export` prefixes. Entries override inherited values. The executable is
located using the original PATH before applying those overrides.

## Output and exit status

Management commands accept `--json` and emit one JSON document. Failures contain
`ok: false` and a sanitized `error`. Run rejects `--json`: successful execution
replaces the launcher, and the target owns stdout, stderr, exit status, and signals.
Before execution, launcher diagnostics go to stderr without raw SDK or OS errors.

| Code | Meaning | Action |
|---|---|---|
| 0 | Operation succeeded | Continue |
| 2 | Invalid arguments, token input, or missing consent | Correct invocation |
| 3 | Missing store, token, or execution precondition | Configure the prerequisite |
| 10 | 1Password authentication failed | Check the enrolled token |
| 11 | Credential store locked | Unlock it separately |
| 12 | Credential access or file policy denied | Correct access and file protection |
| 20 | Operation failed | Inspect the sanitized diagnostic |
| 22 | Credential mutation interrupted or response lost; outcome unknown | Inspect metadata before retrying |
| 23 | 1Password rate limit reached | Retry later |

After execution, these numbers may also be target exit codes. An offline check
does not guarantee later execution will succeed.

## Security boundary

Credential operations refuse any inherited `OP_SERVICE_ACCOUNT_TOKEN`, even an
empty one. Start from a clean environment; unsetting it cannot erase exposure in
an already-running process. Child environments exclude `OP_SERVICE_ACCOUNT_TOKEN`,
`OP_CONNECT_TOKEN`, and every `OP_SESSION_` variable. Those keys are forbidden in
environment files as well.

The service-account token stays in launcher memory, never constructed arguments
or environments. Application secrets enter the target environment and remain
observable through process inspection. Targets may print secrets; no masking is
promised. Same-user malicious code, privileged inspection, memory dumps, and
compromised credential stores are outside this protection. Go strings and SDK
copies are not guaranteed to be securely erased. Successful execution replaces
the launcher's address space.
