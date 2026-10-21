<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# Releasing op-go

**Terms:** A Homebrew tap holds package recipes; a bottle holds prebuilt software.
Debian packages use apt repositories for upgrades. Developer ID is Apple's
distribution signing identity; notarization is Apple's separate malware check.
A GitHub environment groups deployment secrets and approval rules.
See [GLOSSARY.md](GLOSSARY.md) and [RELEASE-TRAIN.md](RELEASE-TRAIN.md).

This process follows the shared signing template and the paniolo apt/Homebrew
pattern. Read [VALIDATION.md](VALIDATION.md) for the qualification evidence and
its limits before each release.

## Distribution

| Platform | Build | Distribution |
|---|---|---|
| macOS Apple silicon and Intel | universal Developer ID-signed binary | notarized/stapled disk image, tar archive, Homebrew universal bottle |
| Linux amd64 and arm64 | separate static Go binaries | tar archives, Homebrew bottles, Debian packages, signed apt pool |

Every downloadable package has a SHA-256 sidecar. Go binaries embed the stable
version, source commit and UTC commit date. Build paths are removed with
`-trimpath`, and archive metadata contains no local owner names or paths.

macOS signatures use the same application identifier as local builds. The SDK's
WebAssembly compiler requires the executable-memory entitlement; the signed
offline SDK test runs before packaging, including a separate Intel execution.
Do not strip, rewrite or re-sign binaries after notarization. A standalone CLI
cannot carry a stapled ticket: tarballs and Homebrew installations use Apple's
online ticket lookup. The disk image is the stapled distribution container.
See [Apple's notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).

## One-time setup

1. Merge the companion homebrew-tap changes first. The release workflow pins the
   reviewed tap commit containing its checksum-validating formula generator.
   The first successful op-go-release dispatch creates Formula/op-go.rb; there
   is intentionally no formula pointing at nonexistent assets before that.
2. Create a protected `release` GitHub environment with a required maintainer
   reviewer and tag deployment rules. Keep the publication variable
   `RELEASE_QUALIFIED` unset until qualification is complete. An unqualified tag
   fails before building or publishing; manual dry runs remain available.
3. Add the credentials below. Reuse the existing Developer ID certificate via
   the shared setup; export only that identity in Keychain Access, not every
   identity in the login Keychain. Create a dedicated notarization Team API key
   for op-go, following the shared per-project convention.
4. Enable GitHub Pages with source **GitHub Actions** and the github-pages
   deployment environment. Review the apt public-key fingerprint before making
   the first package repository available.
5. Require the `release-infrastructure` check alongside the two existing native
   checks in branch protection. It validates workflows, scripts, packaging,
   signed apt metadata, an actual isolated apt installation and profile drift.

| Secret | Scope | Contents |
|---|---|---|
| MACOS_CERT_P12 | release environment | base64 Developer ID Application certificate and private key export |
| MACOS_CERT_PASSWORD | release environment | export password |
| MACOS_NOTARY_API_KEY_P8 | release environment | base64 op-go App Store Connect Team API key |
| MACOS_NOTARY_KEY_ID | release environment | that key's ID |
| MACOS_NOTARY_ISSUER_ID | release environment | issuer UUID |
| HOMEBREW_TAP_DISPATCH_TOKEN | repository | fine-grained token with Contents:write on homebrew-tap |
| APT_SIGNING_KEY | repository | ASCII-armored dedicated signing private key, without a passphrase, for unattended index refresh |

The macOS job imports into a temporary Keychain and removes it afterward. It
never exports a developer's installed identity. Secrets must not appear in
command arguments supplied by maintainers, logs, artifact folders or source.
Apple's import utilities receive the temporary Keychain and certificate-export
passwords as process arguments on disposable runners; the passwords are masked
and removed with signing material. This does not change op-go's prohibition on
service-account tokens in arguments. Only package files and the nonsecret notarization
result are uploaded, never the imported keys. Forks do not deploy the apt site.

## Dry run

After the infrastructure is merged and credentials exist, run:

```sh
gh workflow run release.yml --repo curtisgalloway/op-go --ref main -f version=0.1.0
```

This builds, signs, submits to Apple's notarization service, packages, installs
and tests candidates. It uploads workflow artifacts but creates no GitHub
Release, tag, Homebrew update or Pages deployment. The version is a candidate;
running a dry run does not reserve or publish it. Watch the run and retain its
channel logs and JSON verdicts in the gitignored release-logs directory.

Normal CI needs no signing secrets: it tests the packagers with disposable data
and keys. Cross-compilation alone is not install validation. Required release
jobs run the actual macOS and Linux binaries on each native architecture, pour
Homebrew bottles, and install Debian packages. The apt check uses its own config,
sources, keyring, cache, package database and install root; it cannot change the
developer's system sources. Local Linux checks may use disposable Apple containers.

The profile checker pins every source that determines this process. After editing
one, reread the corresponding profile section, update its description, then run:

```sh
python3 scripts/check-release-profile.py RELEASE-TRAIN.md --update
python3 scripts/check-release-profile.py RELEASE-TRAIN.md
```

## Approve and publish

Run the release-train skill from an isolated release worktree. Require all
channels to pass, review uncovered historical regressions, and complete the
real-store and live-account checks in VALIDATION.md. A passed offline test is
not evidence that Keychain upgrades or a real service account work. Leave
`RELEASE_QUALIFIED` unset while those checks are incomplete.

To publish before qualification, set the repository variable
`RELEASE_PRERELEASE` to `true` instead. The tag then creates a GitHub
pre-release whose notes say it is unqualified, and the workflow skips the
Homebrew tap dispatch and the apt rebuild: the apt pool takes stable releases
only, and the tap treats every tag it receives as stable. Unset the variable
before the first stable release, or that release is published as a
pre-release too.

Once qualified, set the repository variable to `true`. Obtain explicit approval
for the chosen stable version, merge the candidate into main through its PR,
and create an annotated vX.Y.Z tag on that merged commit. Pushing the approved
tag triggers the workflow. It rejects non-stable versions and commits outside
main; all build/install jobs must pass before publication. The release
environment supplies the final maintainer approval gate.

One job creates the release and notes. The tap dispatch then verifies every
archive and checksum and updates the formula, refusing downgrades and changed
contents at an existing version. Homebrew bottles include universal macOS and
explicit Linux architecture pins so Linux never receives the macOS bottle.
The apt workflow downloads the latest five stable releases, verifies Debian
checksums and regenerates signed indexes. Its weekly schedule refreshes the
30-day expiry even when there is no new release. Missing signing material fails
the deployment rather than replacing the site with an empty repository.

## Verify publication and recovery

The release workflow downloads published archives from GitHub and runs the
installed CLI smoke contract on all four native runners. Separately watch the
Homebrew bump workflow and Pages deployment: dispatch acceptance alone is not
successful publication to those channels. In disposable hosts, install through
the public Homebrew and apt commands in the README and run the smoke contract.
Preserve logs and record each channel's result before calling the release done.

If a channel update fails after the GitHub release exists, retain the immutable
release and retry the affected manual workflow after correcting the cause.
The tap's manual workflow accepts the exact release tag; docs.yml reconstructs
the apt pool from releases. Do not delete or rewrite published tags to hide a
failed verification. File a sanitized issue with the reproduction instead.

The signed binary's identity should remain stable across versions. Users whose
tokens were enrolled by an ad hoc build need a one-time Keychain trust migration;
upgrading the formula must never delete, replace or automatically re-enroll their
token. The service-account token remains outside process arguments and the
launcher environment.
