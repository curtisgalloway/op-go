<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# macOS and Linux release qualification

**Terms:** A network namespace is a separate set of Linux network interfaces and
routes. D-Bus is the local messaging service used by GNOME Keyring. A checkpoint
pauses an instrumented test process until its observer finishes inspecting it.
A CONNECT proxy forwards encrypted TLS traffic without decrypting it. SDK means
the official 1Password library. See [the glossary](../../GLOSSARY.md).

These scripts are opt-in qualification tools, separate from default tests. They
require a dedicated test account for live runs and never install system software.
Synthetic runs need no real credentials. Logs, tokens, account IDs, and generated
binaries must not be checked in. Use the gitignored `release-logs/` directory for
local artifacts. Keep every report under a new filename to preserve failures.

## Build once from a committed revision

From the repository root, on either supported platform, run the following. The
output directory must not already exist. Go and Python 3 are required. On macOS,
the configured Developer ID signing identity must be available; missing signing
credentials are an error, never a reason to use ad hoc signatures.

```sh
python3 scripts/qualification/build.py --output release-logs/qualification-build
```

The builder archives committed `HEAD` into a separate directory, builds there,
and writes `manifest.json` with source revision, toolchain, and executable hashes.
Uncommitted source changes are deliberately excluded. The baseline and candidate have different embedded development versions but
the same source revision. The candidate has no instrumentation; the instrumented executable is a separate test artifact, never
something to publish. The native macOS signing script runs its signed offline
SDK validator for both CLI builds. Probes use the same signing identifier,
identity, hardened runtime and entitlements. Offline candidate smoke tests run
on both platforms. These local builds are not notarized release packages.

## macOS operation

`run_macos.py` temporarily makes a disposable Keychain the user's default.
It never locks the login Keychain or edits its entries, but another application
creating credentials during that interval could use the temporary default.
Close those applications first. The script asks before switching, saves recovery
commands, restores and verifies the original default/search list, and deletes
only the test Keychain. If restoration fails it preserves the temporary store.
SIGKILL or power loss requires the saved recovery commands.

First run the synthetic checks. These automate hidden terminal input with a
pseudo-terminal, observe every reported instrumented worker at request/result
checkpoints, and exercise replacement, retrieval, synthetic successful launch,
removal, and locked/denied access. They do not authenticate to 1Password.

```sh
python3 scripts/qualification/run_macos.py --synthetic --binary release-logs/qualification-build/candidate --instrumented release-logs/qualification-build/instrumented --probe release-logs/qualification-build/probe --report release-logs/macos-synthetic.json
```

After that passes, set the dedicated test item's harmless value as described
below and run the live network checks in your terminal. Enter the service-account
token only at op-go's hidden prompt. The observer obtains its comparison token
over a private pipe and retains it only in memory. This run tests a same-path signed upgrade, twenty name/ID lookups, the candidate
at the default and five-second deadlines, separate instrumented initialization
and resolution stalls, and restored-network controls. It prompts for nonsecret
vault/item IDs unless `--ids` supplies a private JSON file. Add `--network-only`
to skip upgrade/lookup checks that already passed against these candidates.

```sh
python3 scripts/qualification/run_macos.py --live --binary release-logs/qualification-build/candidate --instrumented release-logs/qualification-build/instrumented --probe release-logs/qualification-build/probe --report release-logs/macos-network-live.json
```

The macOS observer reads arguments/environments with `ps` at synchronized
checkpoints; it rejects failed reads instead of treating them as clean evidence.
Coverage applies to those processes and checkpoints, not arbitrary memory or
every instant of the uninstrumented candidate. A per-process loopback proxy
provides verified TLS forwarding without host firewall, DNS or proxy changes.
Unlike Linux, macOS has no network namespace in this harness: each stalled test
must show an actual held application reply in the relay counters. A pass with
no such evidence is not accepted.

## Linux operation

The existing `run.py` uses private D-Bus sessions, disposable GNOME Keyring stores,
and a private network namespace. Obtain approval for its privileged namespace
setup. It does not modify desktop credentials or host firewall/DNS configuration.
Read the local-operation section below for live IDs, reports and recovery.
Run `--synthetic` first; `--preflight` checks namespace/verified HTTPS forwarding;
then run the live checks. Use `--network-only` for an affected-check rerun.
All four executables from the shared builder are suitable for those arguments.

## Automated tests and credential-free transport checks

On both platforms, the portable regression tests verify TLS framing, forwarding,
checkpoint-observer failure handling and cleanup. The process-report regression
uses Linux `/proc` and explicitly skips on macOS; Linux CI must run it.

```sh
python3 -m unittest discover -s scripts/tests -p 'test_qualification_*.py' -v
python3 scripts/qualification/check_transport.py --probe release-logs/qualification-build/transport-probe --report release-logs/transport-check.json
```

The second command takes about 45 seconds and uses a local disposable TLS server,
not a real account. It distinguishes a handshake timeout from a stalled request.
Its success does not replace either platform's live SDK test.

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
credentials from the selected platform store (macOS Keychain or Linux Secret Service) using the existing credential worker.
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

The relay permits TLS negotiation before holding application replies. It examines
only client TLS record headers: TLS 1.3's first encrypted record carries Finished,
while the next carries application traffic; TLS 1.2 exposes a distinct encrypted
Finished record type. Record payloads are neither decoded nor logged. Framing
tests include fragmented records. A separate credential-free Go transport probe
uses verified local TLS and HTTP trace callbacks to verify that the handshake
and request write finish before the stall. This avoids mistaking Go's built-in
ten-second TLS handshake timeout for the launcher's total SDK deadline.

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
`--network-only` performs fresh hidden enrollment, network controls/stalls, and
removal without repeating the lookup matrix or consent lifecycle. Use a new
report filename to preserve prior failure evidence. `check_transport.py` tests
the old handshake-stall behavior and the repaired relay with a disposable local
TLS server and no account credentials; those results are not SDK qualification.
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
Each network attempt saves counters, child-marker state, expected/actual status,
elapsed time, phase checkpoints, and surviving observed process IDs even when a
status assertion fails. Sampling still cannot prove that an unobserved process
never existed. TLS establishment uses verified certificates in both the fixture
and live paths; the fixture trusts only its own disposable server certificate.

SIGINT/SIGTERM/SIGHUP restore terminal settings and initiate cleanup. SIGKILL,
power loss, or a controller failure can bypass cleanup. In that case, retain the
report and inspect its temporary directory and private daemon PIDs. Before
terminating a recorded PID, verify its executable and command arguments still
refer to the report's exact temporary directory; PIDs can be reused. Stop only
those private processes, then remove only that directory. Never apply recovery
operations to the desktop bus or keyring. If echo is disabled after a hard kill,
restore it locally with `stty echo` before entering further input.
