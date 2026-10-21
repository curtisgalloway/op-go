<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# Linux network and process qualification

**Terms:** A network namespace is a separate set of Linux network interfaces and
routes. D-Bus is the local messaging service used by GNOME Keyring. A checkpoint
pauses an instrumented test process until its observer finishes inspecting it.
A CONNECT proxy forwards encrypted TLS traffic without decrypting it. SDK means
the official 1Password library. See [the glossary](../../GLOSSARY.md).

These scripts are opt-in qualification tools, separate from default tests. They
require an existing GNOME Keyring installation and dedicated test account. They
do not install software, use the desktop keyring, or change host firewall/DNS
configuration. Obtain approval before using the privileged namespace setup.

## Builds and evidence boundaries

Build the release candidate from a clean source commit with the release build
script and exact version/commit/date metadata. Preserve it separately from the
installed executable. Record its SHA-256, Go version, OS, and provider version.

`prepare.py` generates a Go overlay in a temporary directory. Building with that
overlay produces a **separate instrumented executable**; it does not edit the
release CLI source. Its checkpoint package reports only a phase and process IDs
over a private Unix socket, waits for inspection, and fails closed if the observer
cannot acknowledge it. The overlay also provides an explicitly enabled synthetic
resolver fixture for testing successful execution without a real token. That
fixture is never enabled for live checks and is absent from the release candidate.

The probe under `probe/` is a minimal SDK-only comparison executable. It retrieves
credentials from the isolated real keyring using the existing credential worker.
Its observer export mode writes only to a supplied private pipe, never stdout,
arguments, an environment variable, or a token file. The observer retains the
comparison token only in memory. Its ordinary mode emits sanitized status,
category, phase, and elapsed time, never provider errors or resolved values.

Instrumented worker coverage checks correlate every parent-reported worker PID
with request/result checkpoints. A deliberately timed-out worker is instead
accounted for by its request checkpoint and confirmed exit. This evidence applies
to the instrumented build. The actual candidate gets process-tree sampling across
all threads plus a synchronized checkpoint in its test child after execution;
sampling does not guarantee observation of every short-lived candidate worker.
Neither approach establishes universal absence from memory/debugging interfaces.

## Controlled network path

`run.py` starts an unprivileged host-side Unix-socket relay. Its approved `sudo`
operation creates a fresh network namespace, enables only that namespace's
loopback, and drops to the original UID/GID before executing any credential code.
The namespace has no external interface or route. A loopback proxy bridges to
the relay, which connects only to port 443 on the production 1Password domains.
TLS verification remains enabled; encrypted payloads are forwarded, never logged
or inspected. The relay records only connection/read/held-reply counters.

Transport suitability was checked in the pinned source: onepassword-sdk-go
v0.4.1 uses Extism v1.7.1, whose HTTP host function creates context-bound Go
requests and calls `http.DefaultClient`. The default Go transport supports the
per-process proxy environment used here. No host-wide proxy settings change.

The candidate first demonstrates successful exact-value delivery. Each stalled
run must return 20 near the requested deadline, have an established outbound
connection, forwarded client traffic and a held reply, and leave no child marker.
Both the normal 30-second deadline and explicit five-second deadline are checked;
the allowed measured overhead is five seconds, including credential access and
observer work. A restored-network control must succeed. Separate instrumented
checks distinguish the first-network phase and stop replies only after SDK
initialization, requiring a resolution checkpoint and an actually held reply.
Initialization-only evidence must never be labeled resolution evidence.

The lookup investigation makes five fresh-process reads per name/ID combination,
spaced one second apart, checking the exact harmless value. Authentication/rate
errors stop the run without retries. Other lookup failures trigger a bounded
SDK-only comparison. An official CLI comparison must not bypass its supported
credential handling or this project's ban on token arguments/environments. A
clean matrix means historical intermittency was not reproduced, not fixed.

## Local operation and recovery

`run.py --synthetic` requires no credentials and uses only disposable keyrings.
The live mode requires a local terminal for op-go's hidden prompts and reuses
the enrollment/consent/lock/unlock/removal lifecycle in `validate-linux-real.py`.
`--preflight` verifies the namespace proxy's HTTPS connectivity without credentials.
Provide candidate, instrumented, and probe binaries, a local nonsecret JSON file
with `vault`/`item` IDs, and a private report path. Keep identifiers and local
reports out of published artifacts. The dedicated field's expected value is the
harmless `op-go-test-value`.

The final JSON report includes verdicts, instrumented phases/process IDs, binary
hash, temporary-store location, and cleanup status. The outer controller adds
relay/namespace cleanup evidence. Preserve reports alongside the build provenance.
No process dumps, packet payloads, credential lengths, or token fingerprints are
recorded. A normal failure stops testing and destroys only the temporary keyring;
it never retries authentication or changes the desktop store.

SIGINT/SIGTERM/SIGHUP restore terminal settings and initiate cleanup. SIGKILL,
power loss, or a controller failure can bypass cleanup. In that case, retain the
report and inspect its temporary directory and private daemon PIDs. Before
terminating a recorded PID, verify its executable and command arguments still
refer to the report's exact temporary directory; PIDs can be reused. Stop only
those private processes, then remove only that directory. Never apply recovery
operations to the desktop bus or keyring. If echo is disabled after a hard kill,
restore it locally with `stty echo` before entering further input.
