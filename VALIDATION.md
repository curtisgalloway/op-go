# Validation status

**Terms:** SDK means the official 1Password Go library. cgo connects Go to native
system libraries. D-Bus is the local messaging protocol used by Linux Secret
Service. See [GLOSSARY.md](GLOSSARY.md).

This development implementation has automated evidence for its command and
credential-transport behavior, dedicated-account checks on macOS and Linux,
and a user-operated macOS signed-build upgrade check. It has not completed
signed-release qualification. Results apply to the tested builds, operating
systems, and credential stores, not every supported platform.

## Observed checks

- The first macOS live network run stopped at the pre-stall exact-value control:
  status 10 after 1.685 seconds, before any network-stall attempt. The original
  private report was inspected and preserved. Its relay was in pass-through
  mode, with one connection, one application connection, four client records,
  and zero held replies. The source maps SDK initialization failures to status
  10; this does not independently establish invalid credentials. No checkpoint
  or child execution was observed, and the report retained no surviving observed
  process. The temporary Keychain default/search list were restored and cleanup
  succeeded. No actual macOS SDK stall has passed.
- The subsequent explicit macOS direct control also failed: status 10 after
  1.621 seconds, without a proxy or a network-stall attempt. Hidden enrollment
  and private observer transport passed. No child checkpoint or surviving
  observed process was recorded; cleanup succeeded with no reported errors.
  Both attempts used candidate SHA-256
  `b9cad8c672c4b0dc916e91f7e92248a5f5b45df08a250aafd27e0341c71f5402`.
  Product source, dependencies, and signing scripts are unchanged between the
  earlier successful source `f3d46f2` and this build's source `071cbe5`.
  Failure without forwarding rules out the qualification proxy as a necessary
  cause, but did not identify the initialization error. No automatic
  authentication retry was performed.
- The operator subsequently confirmed the test token had expired. With a renewed
  token, the same candidate passed the direct control on October 21, 2026:
  all 14 recorded checks passed, including exact-value delivery in 3.621 seconds,
  output redaction, the child-after-exec checkpoint, enrollment removal, and
  missing-enrollment status 3. Cleanup succeeded with no reported errors or
  surviving observed processes. This supports expired credentials as the cause
  of the preceding initialization failures. The direct run observed no credential
  workers and does not expand process coverage or qualify network stalls;
  the live network checks remain outstanding.
- The checked-in macOS qualification runner was exercised from build source
  `071cbe5` with Go 1.27.3. Its synthetic run passed all 62 recorded checks,
  including hidden terminal enrollment and echo restoration, piped replacement,
  synchronized worker request/result observation, successful synthetic launch,
  removal, locked status 11, denied status 12, and child suppression. Fifteen
  workers were counted across the regular instrumented operations; the separate
  hidden-enrollment check also required matching request/result observations and
  confirmed exit. No sentinel exposure was observed at those checkpoints.
  This is instrumented synthetic evidence, not a claim about every instant of
  the unmodified candidate. The original Keychain default/search list were
  restored and the disposable Keychain removed; the report confirms cleanup.
- The checked-in credential-free TLS fixture also passed on macOS: handshake
  withholding reproduced the separate transport timeout at 10.014 seconds;
  withholding application replies after verified TLS/request writing exercised
  context deadlines at 30.003 and 5.001 seconds. Restored forwarding succeeded.
  These local transport-fixture results do not qualify a real macOS SDK network
  stall. The checked-in live runner is prepared but still requires local hidden
  token entry; it must not be recorded as passed before it runs.
- A subsequent user-operated macOS run completed 29 checks using two universal
  Developer ID-signed binaries built with Go 1.27.3 from exact source commit
  `f3d46f2391cec2147ca1d14633a6fc8b7d7accaa`. The `0.1.0-dev` baseline SHA-256 was
  `696251cf1b0c1d79807dccb2d3ce758b23e8a00ccf0a0e53c058472ffc796b0f`;
  the `0.1.1-dev` candidate SHA-256 was
  `3aa2b88fffdb6c873228a2b45a469413f1a6c036318075fdd191238155cedccd`.
  Both binaries passed signature, embedded-version and source checks, the
  signed offline SDK validator, and offline CLI smoke checks. After enrollment
  and exact live delivery, replacement at the same executable path retained
  access without re-enrollment. The user confirmed no new permission prompt
  or trust repair. All 20 fresh-process lookups passed: five each with vault/item
  names/names, names/IDs, IDs/names, and IDs/IDs. Each asserted the exact harmless
  test value and absence of authentication variables. Removal succeeded and
  doctor then returned status 3. This pins the development-build upgrade
  evidence to a source commit; it does not establish notarized-package upgrade
  behavior or explain the historical lookup intermittency.
- Inspection of that run's saved JSON report found 1,372 successful process
  samples across 24 sampled operations, 15 process-read errors, and no detected
  token in sampled arguments/environments or captured command output. No
  credential worker was observed. Consequently, worker coverage is incomplete;
  the absence of detected exposure must not be read as a complete security
  qualification. Enrollment used hidden Python input piped to `enroll --stdin`,
  so this observer did not exercise op-go's interactive hidden-enrollment path.
  No real SDK network-stall test was performed.
- Linux follow-up qualification uses clean merge
  `f3d46f2391cec2147ca1d14633a6fc8b7d7accaa`, matching the coordinated macOS
  source, with Go 1.26.10, Ubuntu 26.04.1 amd64, and GNOME Keyring 50.0. The
  candidate embeds that full commit and UTC source date `2026-10-21T02:13:50Z`;
  its SHA-256 is
  `9691a63ffbfb2a624a99c2a7db438effa739137ebc33d25eb3fb2b95c5558896`.
  Automatic Go VCS discovery encountered a non-repository ancestor in the
  isolated-worktree environment, so the build disabled automatic VCS stamping
  and used the release script's explicit, independently checked linker metadata.
  Installed binaries were preserved. The existing real-keyring harness passed
  its synthetic lifecycle and private-policy denial runs on this unmodified
  candidate, including locked status 11, denied status 12, actual stalled-store
  timeout, terminal restoration, and cleanup. The offline CLI smoke contract
  and release-profile consistency check also passed.
- The opt-in tools in `scripts/qualification/` add private network forwarding,
  a bounded lookup matrix, and synchronized process checkpoints. The pinned
  SDK transport was inspected: Extism v1.7.1 sends context-bound requests through
  Go's default HTTP client. An approved disposable network namespace containing
  only loopback reached HTTPS through the private Unix-socket relay with
  certificate verification enabled. This credential-free preflight proves the
  isolation/forwarding setup, not an actual SDK network timeout.
- A separate instrumented build, created through a source overlay, passed
  hidden-terminal and piped synthetic enrollment, replacement, retrieval, and
  successful launch using an explicitly enabled synthetic resolver fixture. All 35 instrumented
  credential workers were correlated with request/result checkpoints or,
  for one deliberately canceled worker, a request checkpoint and confirmed
  exit. The observer found no synthetic token in the inspected arguments or
  environments; no raw process data was recorded. This covers those synchronized
  phases of the instrumented build, not every instant or every worker of the
  unmodified candidate. The temporary keyring and private daemons were cleaned up.
  Normal/race Go tests, vet, and pinned vulnerability scanning passed. Script
  tests passed except for the apt-repository test, skipped because its tools were
  unavailable.
- The subsequent live run passed all twenty fresh-process reads (five for each
  name/ID combination), exact harmless-value comparisons, authentication-variable
  filtering, sampled process exposure checks, and synchronized post-exec child
  observation. Historical lookup intermittency was not reproduced, not proven
  fixed. The first network-stall test then failed its status assertion: expected
  20, received 10 after 11.459 seconds. Its 29.5–35-second timing assertion was
  not reached. The original report is preserved separately. One held relay reply
  confirms traffic reached the forwarding path, but the relay stalled TLS before
  handshake completion. Go's default transport has a ten-second TLS handshake
  timeout. Source-based attribution places the resulting status 10 on the SDK
  initialization error path; the failed uninstrumented run has no direct phase
  checkpoint. This is a demonstrated test setup/expectation error, not evidence
  of a broken thirty-second launcher deadline. Initialization's generic status
  10 must not be interpreted as proof of an invalid token.
- That failing harness version raised before recording the explicit child-marker
  and worker-exit checks. No additional child checkpoint appears, and source flow
  indicates initialization failed before exec after credential-worker reaping,
  but independent final observations were not retained. The report confirms
  keyring/relay cleanup and namespace-controller exit; subsequent inspection
  confirmed the temporary keyring and its private daemon PIDs were absent.
  The five-second SDK stall, restored-network control, and instrumented
  resolution-stage stalls did not run in that attempt; the separate retry below
  supplies their evidence.
- The relay now permits TLS negotiation before holding application replies;
  deadline/status assertions are unchanged. A credential-free local TLS transport
  reproduction measured the original behavior at 10.013 seconds with no completed
  handshake and an unexpired thirty-second context. The repaired forwarding path
  completed certificate verification and request writing, then hit context
  deadlines at 30.026 and 5.000 seconds; a restored-forwarding control succeeded.
  These are transport-fixture results, not SDK or real-account timeout evidence.
  Targeted framing/forwarding and failure-evidence regression tests passed. The
  harness now preserves attempt diagnostics before raising and supports a
  network-only rerun without repeating the successful lookup matrix.
- The subsequent live network-only retry passed all 77 recorded checks against
  the same unmodified candidate hash above. Actual pending application replies
  were observed for each stall with TLS verification enabled. The candidate
  returned status 20 at 30.048 seconds for its default deadline and 5.023 seconds
  for `--timeout 5s`, within the unchanged 29.5–35 and 4.5–10-second bounds.
  Exact-value controls before and after the stalls passed. The separate
  instrumented build identified the first-network stall as SDK initialization
  (status 20 at 5.023 seconds), and independently exercised secret resolution
  after initialization (status 20 at 30.044 and 5.022 seconds). Its restored-network
  exact-value control also passed. Every stall retained an absent child marker
  and no surviving observed process; all five instrumented credential workers
  had synchronized request/result observations and confirmed exit. No token
  exposure was detected in the sampled arguments/environments, synchronized
  checkpoints, or captured output. Uninstrumented process sampling remains
  limited to observed processes and instants; it is not universal coverage.
  Approved removal succeeded and doctor returned missing-enrollment status 3.
  The report confirms isolated keyring/relay cleanup, namespace-controller exit,
  and an unchanged host network namespace. Subsequent inspection found the
  temporary store, private daemon PIDs, and all observed process PIDs absent.
  The original failure report remains unchanged; the lookup matrix was not
  repeated. These live SDK results are separate from the store-timeout and
  credential-free transport-fixture results.
- PR #6 CI subsequently reported reachable standard-library vulnerability
  `GO-2026-6809` in Go 1.26.9 on both native platforms: compromised intermediate
  certificates in `crypto/x509`. The minimum Go version is now 1.26.10, the
  scanner's reported fixed version. The pinned govulncheck v1.9.0 scan with
  Go 1.26.10 returned no vulnerabilities locally. Race tests, vet, a native
  build, the offline CLI smoke contract, and the release-profile check passed. Earlier
  real-keyring results below remain evidence for their recorded Go 1.26.9
  candidate; they do not qualify a rebuilt release candidate automatically.
- During the 2026-10-20 validation session, the user supplied successful
  terminal transcripts from macOS 27.0.1 ARM64 using a dedicated test service
  account and disposable application value. Hidden enrollment, metadata,
  exact nonempty child-environment delivery, and absence of authentication
  variables passed. The child checked `OP_SERVICE_ACCOUNT_TOKEN`,
  `OP_CONNECT_TOKEN`, and every `OP_SESSION_` variable; the latter two types
  were seeded with harmless dummy values. Approved overwrite and subsequent
  delivery passed. A second Developer ID-signed build changed the embedded
  version from `0.1.0-dev` to `0.1.1-dev`; the script required different binary
  bytes and verified live retrieval without re-enrollment. Removal succeeded
  and metadata inspection then returned missing-enrollment status 3. Both
  builds passed the signed offline SDK validator. These were local signed,
  non-notarized builds, not downloaded release packages; their embedded commit
  and date were `unknown`, so the transcripts do not pin the source commit.
- A second user-supplied macOS transcript verified an isolated temporary
  Keychain with synthetic invalid token data. Locked metadata/read checks
  returned status 11; a restricted item's metadata remained readable, while
  token access returned status 12. Neither failed launch executed its child.
  The user confirmed no graphical permission prompts. The script restored
  the original default Keychain and search list and removed the temporary
  Keychain. These results close the tested platform's locked/denied cases;
  they do not qualify other macOS versions or establish process-exposure
  coverage. The developer's test enrollment was removed by the first script.
- On 2026-10-20, a clean-source Linux amd64 candidate from
  `27de464d7f1f4db40154c2d65abc1daa4ec1d5d2` built with Go 1.26.9 and
  cgo disabled passed real GNOME Keyring 50.0 checks on Ubuntu 26.04.1.
  Its SHA-256 was
  `e031b0aa61c3e643cdee2a2b738bda0476e94aecd8cbfcfdc298a3dd84188087`.
  The existing binary reported base revision `9f760f63abb5` with modified
  source, so a separate candidate was built without replacing it. The desktop
  enrollment was inspected as metadata only and left unchanged.
  `scripts/validate-linux-real.py` used private D-Bus sessions and disposable
  real keyrings. Synthetic enrollment, metadata, retrieval reaching expected SDK
  authentication refusal (10), removal, and missing enrollment (3) passed.
  Locked doctor and run returned 11 in under 0.01 seconds without child execution.
  One wrong password returned 11 without retry; a separate correct attempt
  unlocked. SIGINT, SIGTERM, and SIGHUP at the hidden unlock prompt restored echo.
  A private bus policy denying GetSecret returned 12 without child execution.
  Both runs stopped their private services and deleted their temporary stores.
- In that run, stopping the real keyring daemon with SIGSTOP caused a pending
  doctor operation to return 20 after 5.004 seconds; the daemon was then resumed.
  This exercises an actual stalled store request at the normal five-second
  deadline, not a tiny configured timeout. It does **not** qualify a stalled
  1Password network request. Synthetic-token process-tree sampling found no token
  in sampled arguments/environments during enrollment and failed retrieval/launch;
  no process dumps were emitted. Sampling is not exhaustive, does not cover
  hidden live enrollment or successful live launch, and does not prove every
  short-lived worker was observed. No graphical display was configured for these
  private sessions; desktop prompt behavior was not tested by this run.
  Normal Go tests and vet passed.
- A subsequent user-operated run of the same candidate passed hidden enrollment,
  metadata inspection, and exact delivery of the dedicated test account's harmless
  value into a child, with authentication variables absent. The run seeded
  `OP_CONNECT_TOKEN` and `OP_SESSION_TEST` with harmless values and started without
  `OP_SERVICE_ACCOUNT_TOKEN`. At the decline-overwrite step the user entered
  `yes` instead of `no`; replacement returned 0, while the runner expected 2 and
  stopped. This is a test-input mismatch, not evidence of a consent defect.
  Post-replacement delivery, decline preservation, post-unlock live delivery,
  and interactive removal consent remain untested in this run. Cleanup completed:
  the disposable keyring was deleted and its private services stopped; the
  desktop enrollment was unchanged.
- A second user-operated run completed all 28 recorded live checks for that
  candidate on the same GNOME Keyring version. Hidden enrollment and metadata,
  exact dedicated-test-value delivery, and authentication-variable filtering
  passed. Declining overwrite returned 2 and preserved live delivery; approved
  replacement returned 0 and subsequent delivery passed. Locked doctor and run
  returned 11 in 0.006 and 0.005 seconds respectively, without child execution.
  One incorrect disposable keyring password returned 11 without retry; a separate
  correct attempt unlocked and live delivery passed again. The password was
  generated in memory and supplied through op-go's hidden terminal prompt; the
  desktop password was not used. Declining removal returned 2 and preserved
  delivery; approved removal returned 0 and doctor then returned 3. A genuinely
  stalled store request returned 20 after 5.009 seconds. All three interruption
  checks restored terminal echo. The report recorded successful cleanup, and
  subsequent inspection confirmed the temporary store and both private daemons
  were absent. The first run's incomplete consent checks are thus covered by
  this second run. Neither run qualifies desktop graphical prompt behavior or
  a stalled SDK network request.
- The release infrastructure was exercised locally with disposable candidates:
  a Developer ID-signed universal macOS binary passed signature verification,
  the signed offline SDK validator and the CLI smoke contract. Both Linux
  architectures built with cgo disabled and passed the smoke contract in
  disposable containers; amd64 ran under Rosetta translation. Both packages
  passed authenticated apt download and actual dpkg installation into temporary
  roots. Packaging tests verified archive contents, signatures/checksums,
  Debian metadata, retained versions and 30-day signed index expiry. A real
  Homebrew 7.0.9 Linux amd64 bottle pour, brew test and installed-CLI smoke check
  passed in a disposable container. These candidates were not published.
- On 2026-10-20 the release workflow's dry run (manual dispatch, version 0.1.0,
  commit `7c93609`) passed every build and check job with the provisioned
  `release` environment: Developer ID signing and Apple notarization of the
  universal macOS binary and disk image, both Linux architectures, apt
  installation on both, and the four-runner Homebrew bottle matrix, including
  native Intel macOS execution of the signed SDK validator. Publication jobs
  were skipped, as a dry run requires. The published apt site and automated tap
  dispatch remain unverified until the first tagged release.
- Native macOS 27.0.1 arm64 checks with Go 1.27.2 passed for `9b8ebf6`:
  normal and race tests, formatting, vet, build, and the pinned vulnerability
  scan. CLI smoke checks passed for JSON output, literal environment delivery,
  authentication-variable filtering, exact exit/signal preservation, and invalid
  reference rejection. The tests require an environment without an inherited
  service-account token; one interactive-run test otherwise exercises the
  inherited-token refusal before reaching its fake locked store.
- A rebuilt ad hoc binary could read enrollment metadata but was denied token
  access. Inspection found the enrollment restricted to the previous binary's
  signing hash. The macOS build script now uses Developer ID signing, a stable
  identifier, hardened runtime, and a secure timestamp. It verifies the signature
  and executes the offline SDK validator in a similarly signed test binary
  before replacing the CLI. That validator was terminated without an executable
  memory exception and passed with `allow-unsigned-executable-memory`, required
  by the SDK's current WebAssembly compiler. Normal tests and vet also passed.
  This is local signing validation, not notarization or completed upgrade
  qualification. A one-time trust migration added the signed application;
  updating the signing partition through the API failed authentication even
  after interactive approval. The user completed that targeted update with
  Apple's `security` tool, preserving the old hash and adding the signing team.
  The signed build then passed Keychain retrieval and reached SDK resolution.
  The supplied reference returned status 20 with an unsupported SDK error
  category, so this check establishes repaired credential access, not successful
  live-secret delivery or the cause of the resolution failure. No token
  replacement was attempted.
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
  succeeded. Offline reproduction and the provider documentation confirmed that
  colons and percent-encoding are unsupported in reference names. Local parsing
  now rejects those names with an ID-based correction before credential access.
  Regression tests compare representative syntax with the embedded SDK validator
  and preserve supported names with spaces and field query parameters. These
  parsing failures do not explain the earlier intermittent failures for a
  different item.
- An authorized Linux end-to-end check resolved a nonempty application secret
  through exact vault/item IDs and the user-specified custom field name. The
  rebuilt CLI retrieved its enrolled token from Secret Service and replaced
  itself with a child that verified a nonempty application variable and absence
  of `OP_SERVICE_ACCOUNT_TOKEN`, `OP_CONNECT_TOKEN`, and all `OP_SESSION_`
  variables. The child returned status 0. Only pass/fail was printed; no secret
  value, length, or fingerprint was recorded. This completes the Linux nonempty
  live-secret delivery check, without resolving the earlier lookup intermittency.
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
- GitHub Actions run [38986511016](https://github.com/curtisgalloway/op-go/actions/runs/38986511016)
  passed Linux checks for commit `737ef0c` but failed the new macOS reference
  preflight test. That test assumed `/bin/true`; it now uses its own executable
  and includes the actual error in failure diagnostics. Targeted Linux tests and
  vet pass after the correction. Follow-up run
  [38987885981](https://github.com/curtisgalloway/op-go/actions/runs/38987885981)
  passed both native Linux and macOS checks for commit `9f760f6`.
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
- Follow-up launcher safety tests reproduced credential reads with an already
  canceled context and additional lookups after a timed-out resolver returned
  success. Explicit context checks now prevent both. The result-receive branch
  also checks the SDK deadline so a simultaneous result cannot bypass expiry.
  Fake-time tests cover stalled resolution, parent cancellation, and late success.
  Additional regression cases cover token/NUL exposure guards, partial failure,
  initialization error redaction, empty overrides, and duplicate-reference caching.
- Structured SDK response tests reject an extra unrequested entry. A shared
  offline grammar corpus records local and SDK validity, including deliberate
  query-validation differences; tabs in names are now rejected locally to match
  the SDK. Private D-Bus tests cover mismatched owners, missing/different login
  aliases, and invalid passwords before a secret session opens. CLI tests verify
  interactive run never unlocks and explicit wrong-password unlock never retries.
  The expanded suite passed normal/race tests, vet, formatting, and a native
  Linux build. Native macOS execution of these additions awaits CI.
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

## Qualification summary and remaining checks

| Area | Evidence and scope | Remaining work |
|---|---|---|
| macOS credential lifecycle | User transcripts: enrollment, approved replacement, exact live delivery, filtering, removal on macOS 27.0.1 ARM64 | Does not establish declined-consent behavior or other macOS versions |
| macOS signed upgrade | Source-pinned universal signed development builds retained access without re-enrollment | Notarized-package upgrade remains separate |
| macOS locked/denied reads | Temporary real Keychain; statuses 11/12; no child or GUI prompt | Qualify additional supported macOS versions or explicitly limit support |
| Linux credential lifecycle | Dedicated-account checks, consent, lock/unlock, denial and cleanup on Ubuntu 26.04.1 / GNOME Keyring 50.0, source-pinned amd64 candidate | Desktop graphical prompt behavior and other providers are not established |
| Store timeout | Stopped real Linux keyring daemon; status 20 after about five seconds | Separate from SDK network timeout |
| Process exposure | Linux synchronized synthetic/live checks; macOS synchronized synthetic worker checks and prior live sampling | macOS synchronized live check pending; instrumentation does not establish universal candidate coverage |
| SDK network timeout | Linux live candidate deadlines at 30.048/5.023 seconds; separate instrumented initialization/resolution checks and recovery passed | macOS transport has not been exercised with actual stalled traffic |
| Name/ID lookups | All 20 source-pinned matrix reads passed on each platform | Historical intermittency not reproduced; explicit residual-risk decision required |
| Distribution | Signing/notarization and native four-platform install dry run passed | Final candidate verification and post-publication Homebrew/apt checks |

### Recommended order for closing the gaps

Repeatable build and test commands for both platforms are checked in under
[scripts/qualification](scripts/qualification/README.md). Private reports and
generated binaries remain outside version control. A checked-in test is not
evidence of a live pass until its recorded run completes.

1. **Review and integrate the combined evidence.** The Linux network/process
   branch records both the original TLS-handshake stall failure and the repaired
   live run. Preserve both. The failure was a test-placement error, not proof
   of invalid credentials or a broken thirty-second deadline. Run the targeted
   regression tests and required CI before integrating the qualification tools.
2. **Complete the macOS live observation check.** The checked-in signed
   instrumented build now passes synchronized synthetic worker observation.
   Run its live mode to add successful real-account launch observations. Keep
   those checkpoints distinct from unmodified candidate sampling; never weaken
   the deployed binary's signing protections or claim universal coverage.
3. **Decide macOS network-timeout scope.** Linux now has actual candidate and
   instrumented SDK stall evidence at both deadlines, with verified TLS and
   restored-network controls. For equivalent macOS evidence, adapt the verified
   per-process forwarding path, verify that candidate SDK traffic actually uses
   it, and retain timing, child-marker and cleanup checks without changing the
   shared host firewall. If qualification relies on the shared SDK/transport
   implementation instead, explicitly approve and record that platform limit;
   do not claim a macOS network-stall pass from Linux results.
4. **Decide the bounded lookup outcome.** The planned twenty-read matrix passed
   on each platform. No further broad repetitions are required without a new
   failure. Historical intermittency remains unexplained: document that fact
   and obtain an explicit release decision rather than declaring a fix or
   claiming IDs eliminate the issue. Preserve sanitized error categories if
   a future run reproduces it; do not automatically retry authentication errors.
5. **Verify the final distribution artifacts.** Carry the source-pinned macOS
   development-build upgrade check forward to the notarized candidate packages.
   Keep support claims limited to qualified OS/provider combinations. Re-run
   candidate build/install checks if code or packaging changes. After approval
   and publication, verify the tap update and apt deployment, then install the
   published exact version in disposable environments and check signatures,
   checksums and smoke behavior. Linux qualification skipped apt script tests
   where tools were unavailable; the appropriate CI/disposable environment must
   supply that coverage. Channel dispatch acceptance alone is not a pass.

Real-store and real-account checks remain separate from default tests and
require explicit authorization. No credentials are embedded in examples,
fixtures, logs, or this document. Keep `RELEASE_QUALIFIED` unset until the
remaining pre-publication requirements and any explicit scope decisions have
been reviewed; this consolidation does not approve publication.

## Dependency selection

Pinned direct dependencies are the official 1Password Go SDK, godbus for native
D-Bus, and Go's x/sys and x/term packages. Repository health checks found no hard
rejections. The SDK's score was 4.7/10 (confidence 0.6): regular releases and
multiple maintainers, but slower issue response and limited adoption/advisory
signals. godbus scored 7.1/10 (confidence 0.6); x/sys 7.4/10 (0.5); x/term 5.9/10
(0.2, mostly fallback data). These measure project stewardship, not code security.
Source inspection and the tests above supply the evidence for API suitability.
