# Validation status

**Terms:** SDK means the official 1Password Go library. cgo connects Go to native
system libraries. D-Bus is the local messaging protocol used by Linux Secret
Service. See [GLOSSARY.md](GLOSSARY.md).

This development implementation has automated evidence for its command and
credential-transport behavior and a macOS real-account smoke check. It has not
completed signed-release qualification. A green suite does not prove Keychain
access after a binary upgrade or behavior of every Linux desktop keyring.

## Observed checks

- Native Linux amd64 checks passed with Go 1.26.9 on 2026-10-16: formatting,
  normal and race tests, vet, and build. The private D-Bus tests passed outside
  the agent sandbox; the sandbox prevented their bus from starting. These use
  fake Secret Service data, not an actual desktop keyring.
- Native macOS build, `go vet ./...`, and `go test -race ./...` passed.
- GitHub Actions run [38979510614](https://github.com/curtisgalloway/op-go/actions/runs/38979510614)
  passed on native macOS and Linux for commit `0a09523`, including race tests,
  vet, build, and the noninteractive command contract.
- A manually authorized macOS Keychain check passed with disposable values:
  enrollment, metadata lookup, overwrite, retrieval followed by expected SDK
  authentication rejection, and removal. Enrollment was blocked inside the
  agent sandbox and succeeded outside it. The temporary entry was removed.
- An authorized live macOS run retrieved a service-account token from Keychain,
  resolved a real application secret through the SDK, and executed a child that
  verified a nonempty secret, absence of `OP_SERVICE_ACCOUNT_TOKEN`, and no open
  descriptors above standard input/output/error. The known service-account token
  was absent from 46 targeted `ps eww` samples spanning launch and child execution.
  This sampling does not prove absence from every process-inspection interface
  or cover the short-lived credential worker. The agent's preexisting inherited
  token was removed from the launcher's environment; ancestor exposure remains.
- A manually created Keychain entry was readable as metadata but denied token
  access, even with the executable permitted and then all applications allowed.
  Its access metadata included an Apple-only partition rule. With user approval,
  it was replaced through `op-go enroll`; subsequent reads succeeded. The live
  enrollment was retained at the user's request.
- Live references using both vault/item IDs and both vault/item names succeeded.
  An earlier all-name lookup and two mixed name/ID lookups failed. The official
  CLI also initially failed a lookup with a vault name, then succeeded with IDs.
  The cause of these lookup failures has not been established.
- Linux amd64 and arm64 builds passed with cgo disabled. These are compilation
  checks, not evidence of native Linux execution.
- Built-CLI smoke checks passed with a dummy token: metadata and dry-run JSON,
  literal-environment command execution with exit 42, sanitized SDK rejection
  without command launch, and private-worker invocation refusal without pipes.
- The SDK's embedded WebAssembly reference validator ran successfully offline.
  Its initialization is slower with the race detector; the test allows 60 seconds.
  Normal runs retain the configurable 30-second SDK deadline.
- Parser tests reject duplicate and reserved keys, malformed and embedded
  references, oversized input, and NUL bytes. Literal quotes, dollar signs,
  inline comments, and CRLF behavior are tested.
- Fake-store tests verify no token reads during doctor/dry-run, enrollment and
  removal consent, noninteractive refusal, secret-free errors, and inherited-token
  rejection. Unknown mutation outcomes are distinct from known refusals.
- Private-pipe worker tests verify token transport, authentication-variable
  filtering, timeout enforcement, malformed responses, and lost mutation results.
- Protected-file tests cover permissions, symlinks, nonregular files, size limits,
  malformed UTF-8, and control characters.
- Launch tests verify all-or-nothing resolution, child environment construction,
  SDK initialization timeout, descriptor closure, exact exit status, and signal
  termination. No real service-account tokens are used.
- The Linux adapter's private D-Bus tests cover read/write/delete, metadata-only
  status, locked stores, duplicates, sanitized errors, and deadlines. Identical
  adapter/test source ran against a dedicated fake service on macOS with the race
  detector. Linux CI runs the original platform-specific tests with dbus-daemon.
- On 2026-10-16, `govulncheck` v1.9.0 reported 21 reachable standard-library
  vulnerabilities when built with Go 1.26.0. Raising the minimum Go version to
  1.26.9 cleared the scan: no vulnerabilities found. CI now runs the same pinned
  scanner on both platforms against the current vulnerability database.

The automated tests do not read or modify the user's Keychain or desktop keyring.
CI uses a private D-Bus instance and fake values. No real 1Password account is needed.

## Checks required before a supported release

- Exercise dedicated test items in actual Keychain and Secret Service stores:
  enroll, read, overwrite, remove, locked-store refusal, and denial without prompts.
- Verify Keychain item access with the chosen macOS signing identity and after an
  upgrade. The login-Keychain APIs used to disable interaction and check lock state
  compile but are deprecated by Apple; their behavior must be qualified on each
  supported macOS version.
- Authenticate to 1Password with a dedicated, narrowly scoped test account and
  resolve a dedicated test item. The live smoke check used an existing read-only
  account and application item. Verify timeout behavior during a stalled request
  and investigate the observed name/ID lookup failures.
- Inspect process arguments/environments during enrollment, retrieval, and launch
  with test sentinels on both operating systems. The macOS live launch sampling
  above does not cover enrollment, every retrieval worker, or Linux inspection.

Real-store and real-account checks are intentionally separate from default tests
and require explicit authorization. No credentials are embedded in examples,
fixtures, logs, or this document.

## Dependency selection

Pinned direct dependencies are the official 1Password Go SDK, godbus for native
D-Bus, and Go's x/sys and x/term packages. Repository health checks found no hard
rejections. The SDK's score was 4.7/10 (confidence 0.6): regular releases and
multiple maintainers, but slower issue response and limited adoption/advisory
signals. godbus scored 7.1/10 (confidence 0.6); x/sys 7.4/10 (0.5); x/term 5.9/10
(0.2, mostly fallback data). These measure project stewardship, not code security.
Source inspection and the tests above supply the evidence for API suitability.
