# op-go

Launch commands with 1Password secrets while keeping the service-account token
out of process arguments and environment variables.

**Status: repository scaffold. Secret resolution, credential storage, and command
launching are not implemented yet.** This is an independent project, not an
official 1Password product.

**Terms:** A *service-account token* grants automated access to selected 1Password
vaults. A *secret reference* identifies a stored value without containing it.
See [the glossary](GLOSSARY.md) and [the design](DESIGN.md).

## Intended behavior

The Go implementation will load the token directly from macOS Keychain or Linux
Secret Service, authenticate through the official 1Password SDK, resolve
`op://` references, and execute the requested command. An explicitly selected
protected-file source will support headless Linux.

The service-account token will never be exported. Resolved application secrets
will still be placed in the target command's environment. This protects against
accidental token exposure in process listings, not malicious code running under
the same operating-system account.

## Development

Requires Go 1.26 or newer. From the repository root:

```sh
go test ./...
go vet ./...
go build -o bin/op-go ./cmd/op-go
./bin/op-go --help
```

`--version` and `--skill` are available. `doctor --json` returns a JSON report
with `ready: false` and exits 3 until credential access and launching exist.

## License

[Apache License 2.0](LICENSE). Copyright 2026 Curtis Galloway.
