# op-go

Launch commands with 1Password secrets while keeping the service-account token
out of process arguments and environment variables.

**Terms:** A *service-account token* grants automated access to selected 1Password
vaults. A *secret reference* identifies a stored value without containing it.
See [the glossary](GLOSSARY.md) and [the design](DESIGN.md).

This independent Go CLI supports macOS Keychain, Linux Secret Service, and an
explicit read-only token file for headless use. It is not an official 1Password
product. This is a development implementation, not a released security product;
see [validation status](VALIDATION.md) for the checks and remaining limits.

## Build

Requires Go 1.26.9 or newer. macOS Keychain support also requires Apple's command-line
developer tools and cgo (enabled by default for native Go builds). From the
repository root:

```sh
go build -o bin/op-go ./cmd/op-go
./bin/op-go --help
```

Linux service-account builds can use `CGO_ENABLED=0`. The pinned 1Password SDK
embeds its WebAssembly runtime. A macOS build without cgo can use a token file,
but its Keychain backend reports unavailable.

## Enroll and launch

Start from a shell where `OP_SERVICE_ACCOUNT_TOKEN` is not exported. The tool
rejects that variable, even when empty; removing it cannot undo exposure in an
already-running ancestor process. Unlock the operating-system credential store
before enrollment. `op-go` never opens an unlock dialog.

```sh
./bin/op-go enroll
```

Enrollment reads the token with terminal echo disabled. To supply it through a
pipe, use `enroll --stdin`; never put the token in an argument, shell command
text, or environment variable. Overwriting an existing token requires terminal
confirmation or `--yes`. Enrollment stores the token but does not authenticate
it online.

Use `op-go enroll` to provision the macOS entry. An entry created manually in
Keychain Access can be visible to `doctor` but deny reads with status 12, even
after adding the executable to its allowed applications. Keychain partition
rules can impose additional restrictions; allowing all applications did not
resolve this in manual testing. `op-go` suppresses interactive permission dialogs.

Create `secrets.env` with references such as:

```dotenv
APP_TOKEN=op://example-vault/example-item/credential
APP_MODE=development
```

Preview, check enrollment metadata, and launch a command:

```sh
./bin/op-go dry-run --env-file secrets.env --json -- your-command
./bin/op-go doctor --json
./bin/op-go run --env-file secrets.env -- your-command
```

`your-command` denotes the program you want to run. Dry-run verifies file syntax
and executable lookup without reading the token or resolving secrets. Doctor
checks enrollment metadata only; neither proves that the token can authenticate.

On Linux without a desktop session, explicitly select an externally provisioned
file. It must be a regular file owned by the effective user, have no group/other
permissions, not be a symlink, and contain at most 64 KiB. The final path component
is checked without following symlinks; parent directories must also be trusted.
The file is unencrypted, protected by filesystem permissions, and never selected
as an automatic fallback. `--token-file` accepts only a path, not a token value.
Use `--backend file --token-file /path/to/token` on run, dry-run, or doctor.
Enrollment and removal do not modify token files.

Remove an operating-system-store enrollment with `remove --yes`, or preview it
with `remove --dry-run --json`. The fixed identity is service `op-go`, account
`service-account`. Linux uses the existing default Secret Service collection.

## Environment-file rules

- Exactly one `--env-file` is required for run and dry-run.
- Names use ASCII letters, digits, and underscores; the first character cannot
  be a digit. No whitespace around names and no `export` prefix.
- Values after the first `=` are literal. Quotes, dollar signs, backticks, and
  inline `#` characters are preserved. Only blank lines and full-line comments
  are ignored; CRLF line endings are accepted.
- Only whole-value `op://vault/item/field` or `op://vault/item/section/field`
  references resolve. Embedded references, malformed references, duplicate
  names, NUL bytes, and files over 1 MiB are rejected.
- File entries override inherited variables. The executable is located using
  the original `PATH`, before overrides.
- `OP_SERVICE_ACCOUNT_TOKEN`, `OP_CONNECT_TOKEN`, and `OP_SESSION_*` cannot be
  supplied by the file and are excluded from the command's environment.

## Security and process behavior

The launcher reads the token directly into memory and passes it to the official
SDK. Credential-store operations run in short-lived helpers using private pipes
and a five-second deadline. SDK initialization and all resolution share a
30-second deadline, configurable with `--timeout`. All values must resolve before
launch. The launcher marks nonstandard file descriptors close-on-exec, then
replaces itself with the target; no token-holding supervisor remains.

Resolved application secrets **are** placed in the target environment. They can
be inspected by appropriately privileged programs, and the target can print them.
There is no output masking. This tool does not isolate credentials from malicious
code under the same user account, debuggers, or privileged memory inspection.
Go and SDK memory copies are not guaranteed to be erased before process replacement.
SDK output override `EXTISM_ENABLE_WASI_OUTPUT` is rejected for secret resolution.

Run rejects `--json` and preserves the target's output, exit code, and signal
behavior after replacement. Management commands support JSON. Pre-launch errors
use the documented launcher statuses; status alone cannot distinguish those from
an identically numbered target failure. `--help` and embedded `--skill` list the
complete contract. An interrupted enrollment/removal can report status 22,
meaning its outcome is unknown; inspect the store before retrying.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

Tests use fake stores and credentials. Linux wire tests create a private D-Bus
instance and fake Secret Service; install `dbus-daemon` to run them. They never
connect to the user's service. Native credential-store access and live 1Password
authentication are not part of the default suite.

## License

[Apache License 2.0](LICENSE). Copyright 2026 Curtis Galloway.
