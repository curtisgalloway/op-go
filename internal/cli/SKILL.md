---
name: op-go
description: Inspect the op-go credential-safe command launcher scaffold and readiness.
---

<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# op-go {{VERSION}}

This build is a scaffold. It cannot access credentials or launch commands.
CLI means command-line interface. See the repository glossary for project terms.

## Invocation

```sh
op-go --help
op-go --version
op-go --skill
op-go doctor --json
```

## Exit status

| Code | Meaning | Action |
|---|---|---|
| 0 | Informational command succeeded | Continue |
| 2 | Invalid arguments | Correct invocation |
| 3 | Credential and launch implementation unavailable | Do not attempt secret access |

## Output

Doctor with --json emits one JSON object containing ready and reason, and exits 3.
Human diagnostics go to stderr. No command reads or changes credentials.

## Notes for an agent

Do not describe this scaffold as a working replacement for op run.
