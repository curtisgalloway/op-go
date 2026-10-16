<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# op-go

**Terms:** CLI means command-line interface; SDK means the official Go library
for 1Password. See [GLOSSARY.md](GLOSSARY.md).

Go CLI for macOS and Linux. Read DESIGN.md before implementing credential access.
This repository currently contains a scaffold, not a working secret launcher.

- Never accept or log secret values in arguments, environment, errors, or dry-run output.
- No real credentials in tests. Use fake stores and resolvers.
- Keep credential backends explicit; never fall back to plaintext silently.
- Use gofmt, go test ./..., go vet ./..., and go build ./cmd/op-go.
- Keep --skill embedded and synchronized with actual supported behavior.
- Launcher statuses currently used: 0 success, 2 usage error, 3 missing precondition.
- No tool-specific statuses are assigned yet.
- Keep public artifacts free of personal infrastructure and local filesystem paths.
