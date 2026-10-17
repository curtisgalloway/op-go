<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# op-go

**Terms:** CLI means command-line interface; SDK means the official Go library
for 1Password. See [GLOSSARY.md](GLOSSARY.md).

Go CLI for macOS and Linux. Read DESIGN.md before implementing credential access.
Credential access is implemented. Read VALIDATION.md before claiming release readiness.

- Never accept service-account tokens through arguments or environment variables.
- Never log secret values in diagnostics or dry-run output; only resolved application
  secrets belong in the target environment.
- No real credentials in tests. Use fake stores and resolvers.
- Keep credential backends explicit; never fall back to plaintext silently.
- Use gofmt, go test ./..., and go vet ./.... Run tests without an inherited
  `OP_SERVICE_ACCOUNT_TOKEN`; never print its value.
- On macOS, build the local CLI with `bash scripts/build-macos.sh`. It signs and
  verifies the executable with a stable Developer ID identity and runs the
  offline SDK check under the same protections before replacing `bin/op-go`.
  Keep the signing identity and application identifier stable across rebuilds;
  Keychain enrollment trusts that identity. Never overwrite the local signed
  `bin/op-go` with plain `go build`. Put unsigned diagnostic builds in a temporary
  location. Missing signing credentials are an error, not permission to fall
  back to ad hoc signing. Unsigned builds in disposable CI jobs are fine for
  fake-credential tests, but do not qualify Keychain access or release signing.
  On Linux, use `go build -o bin/op-go ./cmd/op-go`.
- Keep --skill embedded and synchronized with actual supported behavior.
- Launcher statuses: 0 success, 2 usage, 3 missing precondition, 10 authentication,
  11 unlock needed, 12 denied, 20 failed read/timeout, 22 unknown mutation outcome,
  23 rate limited. Successful exec preserves the target status and signal.
- No tool-specific statuses are assigned yet.
- Keep public artifacts free of personal infrastructure and local filesystem paths.
