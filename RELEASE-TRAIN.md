<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# Release train profile: op-go

**Terms:** A release candidate is a build being checked before publication. A
Homebrew tap is a repository of package recipes; a bottle is a prebuilt package.
An apt repository provides signed Debian package indexes for installation and
upgrades. Notarization is Apple's check of signed software. See [GLOSSARY.md](GLOSSARY.md).

Derived from commit 505a47a on 2026-10-16. Executed by the release-train skill;
checked by `scripts/check-release-profile.py`. UNVERIFIED means the specified
distribution path has not completed its full qualification yet.

## Project

- cli: `op-go`
- version source: stable release tag; linker values set version, commit and UTC commit date
- tag format: `vX.Y.Z`; annotated subject `vX.Y.Z: lowercase summary`
- main branch: `main`; protected by PR and required macOS/Linux checks
- release workflow: `.github/workflows/release.yml`
- ci workflow: `.github/workflows/ci.yml`; required checks: test (ubuntu-latest), test (macos-latest)
- bump rules: feat minor; fix/perf patch; build/docs/ci/test alone do not require a release; classify unprefixed commits explicitly
- releaser identity: use the repository's existing GitHub noreply author convention
- log directory: release-logs, gitignored; record each channel's transcript and verdict
- references: shared macOS code-signing convention; paniolo packaging/apt template; existing Homebrew tap dispatch convention

## Hosts

Roles only. Optional machine mappings belong in the gitignored
RELEASE-TRAIN.local.md, never in release artifacts or published logs.

| role | needed by | what it must have |
|---|---|---|
| macos-arm64 | source, universal macOS archive, disk image, bottle | Go from go.mod, Xcode tools, Developer ID identity, project notarization key, Homebrew |
| macos-intel | universal binary and SDK validation, bottle | Intel macOS runner, Homebrew; signed offline SDK test downloaded from build job |
| linux-amd64 | archive, bottle, Debian, apt | native Ubuntu runner or disposable container, Go, Python 3.9+, dpkg-dev, apt-utils, GnuPG, D-Bus |
| linux-arm64 | archive, bottle, Debian, apt | same tools on native arm64 Linux |

GitHub uses macos-15, macos-15-intel, ubuntu-24.04 and ubuntu-24.04-arm.
Apple's container service is approved for disposable local Linux validation.
Rosetta execution is useful evidence but does not replace the native Intel jobs.
Never install candidates over the developer's CLI or use their credential stores.

## Smoke contract

Run `scripts/smoke-release.py` against the installed copy, with the exact candidate
version. The script uses a temporary HOME, working directory and fake file token;
it never accesses a real Keychain, Secret Service store or 1Password account.

| id | check | pass condition |
|---|---|---|
| S1 | `op-go --version` and `op-go --help` | exact release version and launcher help |
| S2 | `op-go --skill` | embedded skill available without checkout files |
| S3 | `op-go doctor --backend file --token-file TEST --json` | private worker reads fake file metadata; permissive file mode is rejected |
| S4 | `op-go dry-run --backend file --token-file TEST --env-file TEST --json -- /bin/sh` | reference keys and literal keys reported without resolving values |
| S5 | `op-go run --backend file --token-file TEST --env-file TEST -- /bin/sh` | literal environment delivered; exit 42 preserved; auth variables removed and inherited service-account token rejected |

There is no app configuration writer to round-trip. S3 changes a temporary file's
permissions, verifies refusal, restores them, and S4/S5 exercise environment files.
The self-invoked credential worker is the bundled helper exercised by S3.

## Channels

### source

- kind: source
- artifact: local signed CLI or Linux native CLI
- workflow job: macos
- host: macos-arm64, linux-amd64, linux-arm64
- build: isolated release worktree; macOS uses `scripts/build-macos.sh`, Linux uses `scripts/build-linux.sh`
- install like a user: copy the built executable into a throwaway prefix, never the user's bin directory
- smoke: S1..S5, normal/race Go tests, vet, formatting and pinned vulnerability scan
- cleanup: remove only the disposable prefix and release worktree after preserving logs
- caveats: real-store migration and live account qualification are separate manual gates in VALIDATION.md

### macos-archive

- kind: zip
- artifact: op-go-vX.Y.Z-darwin-universal.tar.gz and checksum
- workflow job: macos
- host: macos-arm64, macos-intel
- build: universal Go/cgo binary; Developer ID sign with stable identifier, hardened runtime, timestamp and SDK memory entitlement; notarize before packaging
- install like a user: extract into a temporary directory and copy executable into a temporary bin directory
- smoke: S1..S5 on both architectures; signed offline SDK validator on both architectures; verify signature
- cleanup: remove extracted candidate and temporary signing keychain
- caveats: UNVERIFIED full Apple notarization dry run and native Intel execution; standalone executables cannot carry a stapled ticket, so archives rely on Apple's online ticket lookup

### macos-disk-image

- kind: zip
- artifact: op-go-vX.Y.Z-darwin-universal.dmg and checksum
- workflow job: macos
- host: macos-arm64
- build: `scripts/notarize-macos.sh` signs the disk image, submits it to Apple, requires Accepted status, staples and verifies the ticket
- install like a user: mount disk image read-only, copy executable to a disposable prefix, unmount
- smoke: S1..S5 on the copied executable; stapler validate; Gatekeeper disk-image assessment
- cleanup: unmount on success or failure; remove temporary copy
- caveats: UNVERIFIED full notarization and mounted-image install; credentials are not yet provisioned

### homebrew

- kind: homebrew
- artifact: op-go-X.Y.Z.all.bottle.tar.gz, arm64_linux and x86_64_linux bottles, plus per-asset checksums
- workflow job: homebrew
- host: all four native runner roles
- build: `packaging/scripts/package.sh`; generate formula using pinned homebrew-tap script after verifying all six archives against their sidecars
- install like a user: brew install --force-bottle from a temporary tap on disposable runners; formula URLs point at local candidate assets before publication
- smoke: S1..S5 plus brew test; execute both macOS slices and both native Linux builds
- cleanup: discard the runner or container and its temporary tap/keg
- caveats: UNVERIFIED complete four-runner Homebrew matrix; tap integration must be merged before the first dry run

### debian

- kind: deb
- artifact: op-go_X.Y.Z_amd64.deb and op-go_X.Y.Z_arm64.deb with checksums
- workflow job: linux
- host: linux-amd64, linux-arm64
- build: static CGO-disabled Go binaries; `packaging/scripts/package.sh` constructs packages with root-owned metadata and no maintainer scripts
- install like a user: dpkg install in a disposable runner; execute installed usr/bin/op-go
- smoke: S1..S5; verify Debian architecture and package metadata
- cleanup: discard runner or disposable package root
- caveats: Linux desktop Secret Service needs an existing session bus and unlocked store; headless file backend is explicit

### apt

- kind: deb
- artifact: signed pool and indexes at https://curtisgalloway.github.io/op-go/apt/
- workflow job: apt-install
- host: linux-amd64, linux-arm64
- build: assemble both architectures using `packaging/scripts/build-apt-repo.sh`; keep five stable releases; 30-day Valid-Until and weekly rebuild
- install like a user: `packaging/scripts/test-apt.sh` uses a disposable key, isolated apt configuration, authenticated download and actual dpkg installation into a temporary root
- smoke: S1..S5 on installed copy, both architectures; verify signatures, expiry and retained versions
- cleanup: remove test keys, apt configuration/cache and package root; no host apt sources are changed
- caveats: UNVERIFIED published Pages repository and public-key bootstrapping; signing key and Pages setup required

## Archaeology

- issue source: `gh issue list --state closed --limit 200`
- fix commits: review fix/perf subjects and unprefixed safety, parser, worker and Keychain changes since previous tag
- test locations: internal/cli, internal/launch, internal/store; packaging tests under scripts/tests
- how to run: go test ./..., go test -race ./..., go vet ./...; python3 -m unittest discover -s scripts/tests -v
- prove-it-bites: in a separate worktree revert only the relevant fixed source to its parent, require the regression test to fail, restore and require pass
- first release: no prior release tags; include existing cancellation, parsing, process environment and worker transport regressions

## Publish

- gate: follow [RELEASING.md](RELEASING.md); all channels must pass, no unwaived partial results, review VALIDATION.md, and obtain explicit approval before tagging/pushing
- steps: merge tap support first; merge release infrastructure through protected main; provision credentials and protected release environment; workflow_dispatch dry run; review logs and real-store qualification; set RELEASE_QUALIFIED=true only after those gates; annotated stable tag on main; push tag after approval
- automation: tag workflow refuses publication until RELEASE_QUALIFIED=true, waits for every build/install job, creates one GitHub release, dispatches op-go-release to the tap and docs.yml to rebuild apt
- re-verify: archive public URLs are downloaded, checksum-checked and smoke-tested by verify-published on all four runners
- re-verify: watch the tap dispatch workflow, require its version to match, then brew update/install/test in disposable macOS and Linux environments
- re-verify: wait for docs.yml deployment, then use the README deb822 configuration in disposable Linux environments; require `gpg --show-keys` on the downloaded key to match the README fingerprint, apt update and install exact version, then S1..S5
- failure after publication: report channel failure and open a sanitized issue; never silently delete/rewrite a public tag

## Sources

| path | blob | feeds |
|---|---|---|
| `.github/workflows/release.yml` | f0987346b04f | Channels, Publish |
| `.github/workflows/docs.yml` | b3d2d0f08300 | Channels: apt, Publish |
| `.github/workflows/ci.yml` | 442226c5ec7f | Project, Archaeology |
| `scripts/build-macos.sh` | d709e9ae8d5f | Channels: source, macos |
| `scripts/build-linux.sh` | 42b4307b4e5e | Channels: source, debian |
| `scripts/notarize-macos.sh` | c9c0215118ec | Channels: macos |
| `scripts/macos-entitlements.plist` | 6db4ab328095 | Channels: macos |
| `packaging/scripts/package.py` | b88d71fd6d19 | Channels |
| `packaging/scripts/build-apt-repo.sh` | 4a3e093787e0 | Channels: apt |
| `packaging/scripts/test_apt.py` | 7d62a4dcc344 | Channels: apt |
| `scripts/smoke-release.py` | 070182aabddb | Smoke contract |
| `go.mod` | bec09cb1bcdd | Hosts, Archaeology |
| `README.md` | 35e97ba32a21 | Channels |
| `RELEASING.md` | 2a8ad114d3f1 | Publish |
