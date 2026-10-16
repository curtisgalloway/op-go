# Validation status

**Terms:** SDK means the official 1Password Go library. cgo connects Go to native
system libraries. D-Bus is the local messaging protocol used by Linux Secret
Service. See [GLOSSARY.md](GLOSSARY.md).

This development implementation has automated evidence for its command and
credential-transport behavior. It has not completed real-account or signed-release
qualification. A green suite does not prove Keychain access after a binary upgrade
or behavior of every Linux desktop keyring.

## Observed checks

- Native macOS build, `go vet ./...`, and `go test -race ./...` passed.
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
- `govulncheck` reported no known vulnerabilities in the current build graph.

The tests do not read or modify the user's Keychain or desktop keyring. CI uses a
private D-Bus instance and fake values. No real 1Password account is needed.

## Checks required before a supported release

- Execute the full suite on native Linux; CI is configured but was not run remotely
  during local implementation.
- Exercise dedicated test items in actual Keychain and Secret Service stores:
  enroll, read, overwrite, remove, locked-store refusal, and denial without prompts.
- Verify Keychain item access with the chosen macOS signing identity and after an
  upgrade. The login-Keychain APIs used to disable interaction and check lock state
  compile but are deprecated by Apple; their behavior must be qualified on each
  supported macOS version.
- Authenticate to 1Password with a dedicated, narrowly scoped test account and
  resolve a test item. Verify descriptor hygiene after actual SDK network use and
  timeout behavior during a stalled request.
- Inspect process arguments/environments during enrollment, retrieval, and launch
  with test sentinels on both operating systems. Current tests inspect constructed
  environments and private transport, not every OS process-inspection interface.

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
