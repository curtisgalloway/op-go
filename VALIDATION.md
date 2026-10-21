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
| Process exposure | macOS live enrollment/launch sampling and Linux synthetic enrollment/failed-launch sampling | Latest macOS observer saw no workers; interactive enrollment and complete worker coverage remain incomplete |
| SDK network timeout | Automated cancellation tests; no actual stalled-network result | Exercise a real stalled SDK request |
| Name/ID lookups | All 20 source-pinned macOS matrix reads passed; earlier Linux diagnostic matrix also passed | Updated Linux matrix pending; historical intermittency remains unexplained |
| Distribution | Signing/notarization and native four-platform install dry run passed | Final candidate verification and post-publication Homebrew/apt checks |

### Recommended order for closing the gaps

1. **Pin the candidate and preserve evidence.** Integrate the Linux validation
   changes and this macOS record through passing CI. Record the exact candidate
   commit, executable checksums, signing identity, OS and provider versions in
   private run records. The macOS development-build upgrade is now source-pinned; carry that
   check forward to the notarized candidate packages. Do not overwrite an
   existing enrollment merely to make a failed upgrade pass. Keep support claims limited to qualified environments.
2. **Exercise a real SDK network stall.** In a disposable Linux network
   environment, first verify successful resolution with the dedicated account.
   Then delay or drop response traffic for that test process's actual SDK
   connection. Preserve access to the isolated local credential store. Confirm
   the request reached the network and remained pending; an immediate DNS,
   connection-refused, authentication, or certificate error is not a stall.
   Test both the normal 30-second SDK deadline and a shorter nonzero deadline,
   measuring elapsed time and expecting status 20 with no child execution and
   no surviving worker. Allow bounded scheduling/cleanup overhead and document
   it. Do not disable TLS verification, record packet payloads, or alter the
   host's shared firewall. First inspect the pinned SDK's transport support;
   do not assume it honors HTTP proxy environment variables. Repeat on macOS
   or state explicitly that only Linux transport behavior was exercised.
3. **Close the process-observation gaps.** Use synthetic sentinel tokens
   (distinctive disposable strings) to inspect hidden enrollment, replacement,
   credential retrieval, and every private worker on both operating systems.
   Use synchronized test checkpoints where necessary so short-lived workers
   cannot simply escape the observation window. For successful live launch,
   use the dedicated test account; any comparison with its actual token must
   remain in memory and emit only pass/fail. Never persist process dumps or
   token values, lengths, or fingerprints. Verify the child still receives the
   harmless application value and excludes authentication variables. Clearly
   distinguish observations of the actual candidate from instrumented builds;
   sampling alone cannot establish absence from every inspection interface.
4. **Bound the lookup investigation.** On the same dedicated item, compare
   names/names, names/IDs, IDs/names, and IDs/IDs in fresh processes on both
   systems, using supported names and exact-value assertions. The macOS five-run-per-combination matrix passed; run the same bounded
   matrix on the updated Linux candidate and space calls to avoid rate limits. Record only
   timing, sanitized error category, platform and SDK version. Stop on an
   authentication failure or rate limit; do not automatically retry it. On a
   lookup failure, preserve the category and reproduce with a small SDK-only
   program and the official CLI, using their supported credential handling.
   A clean matrix bounds current reproducibility; it does not explain history.
   If the old failure remains unreproduced, document that residual limitation
   and obtain an explicit release decision rather than declaring a fix or
   claiming ID references eliminate the issue.
5. **Finish distribution verification at the appropriate stage.** Re-run
   candidate build/install checks if code or packaging changes. After the
   approved stable release, confirm the tap update and apt deployment, then
   install the published exact version in disposable environments and verify
   checksums, signing and smoke checks. Dispatch acceptance is not evidence
   of a successful channel update. These post-publication checks cannot be
   claimed before assets and repositories exist.

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
