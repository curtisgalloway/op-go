# Validation status

**Terms:** SDK means the official 1Password Go library. cgo connects Go to native
system libraries. D-Bus is the local messaging protocol used by Linux Secret
Service. See [GLOSSARY.md](GLOSSARY.md).

This development implementation has automated evidence for its command and
credential-transport behavior and macOS and Linux real-account smoke checks. It has not
completed signed-release qualification. A green suite does not prove Keychain
access after a binary upgrade or behavior of every Linux desktop keyring.

## Observed checks

- Native Linux amd64 checks passed with Go 1.26.9 on 2026-10-16: formatting,
  normal and race tests, vet, and build. The private D-Bus tests passed outside
  the agent sandbox; the sandbox prevented their bus from starting. These use
  fake Secret Service data, not an actual desktop keyring.
- Authorized real-store checks passed against GNOME Keyring 50.0 on Linux on
  2026-10-16, using disposable values, a private D-Bus session, and temporary
  keyring directories. Enrollment, metadata, exact retrieval through the
  credential worker, overwrite consent, replacement, removal consent, removal,
  and confirmed absence passed. Locked metadata/read/enroll/remove operations
  returned status 11 promptly. A separate private D-Bus policy denied GetSecret;
  the credential worker returned status 12. This verifies bus-policy denial,
  not every desktop keyring's application-access policy. Temporary keyrings were
  removed and their daemons stopped.
- The Linux launcher retrieved a disposable invalid token from the real isolated
  keyring and returned SDK authentication status 10 without launching its child.
  Process-tree sampling during enrollment, retrieval, replacement, removal, and
  this failed launch found no dummy-token sentinel in sampled process arguments
  or environments. Sampling is not exhaustive and does not establish successful
  real-account launch behavior. The existing desktop keyring was locked; its
  metadata check returned status 11. That isolated-store validation did not
  unlock or modify the desktop keyring.
- After user-operated enrollment, an authorized Linux real-account check on
  2026-10-16 retrieved the token from the desktop keyring and resolved an existing
  application item's credential field. The child verified that the variable was
  present and authentication variables were absent. Direct item retrieval
  confirmed that this field's stored value was empty; this does not validate
  nonempty live-secret delivery. The initially requested password field did not
  exist on that item. No secret values were printed.
- Earlier Linux name-based resolutions intermittently failed with generic
  status 3. A bounded diagnostic subsequently succeeded with all four vault/item
  name/ID combinations using both shared and fresh SDK clients (eight reads),
  plus separate cold processes using all names and all IDs (two reads). Every
  result matched the empty field confirmed by direct item retrieval. These
  checks did not reproduce or explain the intermittent failures. At the time, unrecognized
  SDK resolution errors collapsed to status 3, so that status alone could not
  distinguish a missing reference from an operational or authentication failure.
  Resolution now uses the SDK structured-response API: missing and ambiguous
  references receive specific sanitized diagnostics; unclassified failures
  return status 20. A future reproduction still needs error-category evidence;
  the successful checks do not establish that IDs eliminate the failure.
- The structured-resolution change passed normal and race tests, vet, formatting,
  and a native Linux build. Fake responses cover empty values, missing and
  contradictory results, reference error categories, sanitized unknown errors,
  and refusal to retry or launch after failures. Two authorized live checks
  through the changed API confirmed delivery of the existing empty field and
  status 3 with a field-not-found diagnostic for the nonexistent password field.
- An additional authorized Linux check resolved a nonempty credential using
  user-supplied vault and item IDs through the structured SDK API. Because the
  target value was itself a service-account token, it stayed in memory: no
  child was launched and no value, length, or fingerprint was printed. This
  verifies nonempty live resolution, not nonempty delivery into a child
  environment. Both literal and percent-encoded title references for this
  item returned the structured parsing-error category; the exact-ID reference
  succeeded. These parsing failures do not explain the earlier intermittent
  failures for a different item.
- The SSH terminal workflow passed against an isolated GNOME Keyring 50.0:
  explicit `unlock`, enrollment's unlock offer, separate overwrite consent,
  hidden keyring-password and token input, exact token readback, and one
  wrong-password attempt returning status 11 without retrying. Terminal echo
  was restored after SIGINT, SIGTERM, and SIGHUP while waiting for a password.
  Automated fake-service tests cover the private worker's password transport,
  extension signature checks, refusal of unsupported providers, access denial,
  post-unlock lock-state verification, and deadlines. This uses GNOME's private
  password-unlock D-Bus extension, not the standard graphical prompt flow;
  compatibility with other GNOME Keyring versions remains unqualified.
  The actual desktop keyring also passed unlock preflight and reached the hidden
  password prompt; it was canceled before password input, with echo restored.
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
