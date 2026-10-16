# Token handling and command execution

**Terms:** The *service-account token* authenticates to selected 1Password vaults.
The *SDK* is the official Go library. *exec* replaces the launcher process with
the requested program. Keychain and Secret Service are operating-system
credential stores. See [GLOSSARY.md](GLOSSARY.md).

This design is implemented as a development CLI. Platform integration and
packaging must be verified before publishing release security claims. See
[VALIDATION.md](VALIDATION.md) for observed evidence and remaining checks.

## Objective and boundary

Keep the service-account token out of constructed arguments and environments,
including enrollment. Read it directly into memory, pass it directly to the SDK,
and replace the launcher after resolving all requested values. Application
secrets still enter the target environment and remain observable through process
inspection. Same-user malicious code, privileged inspection, debuggers, memory
dumps, and compromised credential stores are outside this protection.

If OP_SERVICE_ACCOUNT_TOKEN is inherited, credential operations must refuse to
proceed and explain how to start from a clean environment. Rejection cannot undo
exposure that already occurred, including exposure in an ancestor process.
Do not claim that unsetting the variable erases the initial environment.

## Credential sources

- macOS: access Keychain through native APIs, including enrollment; never pass
  the token to the `security` command as an argument. Verify item access controls,
  unlock behavior, signing identity, and access after a signed binary upgrade.
- Linux desktop: access Secret Service directly. Require an available session
  service and unlocked collection. No automatic plaintext fallback.
- Headless Linux: explicitly selected, read-only protected-file source. Verify
  ownership and permissions on the opened descriptor, reject symlinks and
  nonregular files, cap input size, and require no group/other access. This is
  filesystem protection, not encryption. External provisioning is responsible
  for the file's lifecycle; system-managed credentials are a suitable candidate.

Enrollment accepts hidden terminal input or an explicitly requested stdin mode.
Never accept the token as a command-line flag or environment fallback. Overwrite
requires explicit consent. Absent or locked stores must produce actionable,
nonsecret errors without waiting indefinitely for an unattended prompt. Do not
claim a stored token is valid unless a documented harmless check has succeeded.
Run and doctor never request an operating-system unlock prompt. Enrollment
also requires an already-unlocked store in v1; users unlock it separately.
Use short-lived self-invoked helpers with private request/response pipes for
all store calls, including file reads; kill and reap them on timeout, without token arguments,
environment variables, or standard-output transport. Bound credential-store operations to 5 seconds and SDK authentication/resolution
to a configurable total timeout, default 30 seconds. Verify the selected APIs
can enforce these bounds before shipping. Doctor is offline by default and
must not retrieve token values to check setup.

Enrollment and removal support dry-run without retrieving or writing tokens.
Removal and overwrite require --yes or explicit terminal confirmation. Token
stdin cannot double as confirmation input. Without a terminal or the required
flag, return usage error 2 rather than prompt. The file source is read-only;
enrollment/removal apply only to operating-system stores.

## Resolution and environment

Use the official Go SDK's direct token authentication and secret-resolution APIs.
Pin the chosen SDK version after verifying packaging, architectures, and Linux
runtime requirements. Audit native dependencies; do not assume a pure Go build.

Define a small environment-file grammar: blank lines, full-line comments,
ASCII shell-style variable names, and KEY=value entries. No shell evaluation,
variable expansion, multiline values, or embedded references. Values are literal;
only a complete value beginning with op:// is resolved. Reject duplicate keys,
NUL bytes, malformed lines, and reserved credential variables. For v1, quote characters, #, $, and backticks in values are literal, not syntax;
only full-line comments are recognized. Preserve the value after the first =,
except the line terminator. Reject export prefixes and whitespace around keys.
Support one explicitly supplied environment file initially; its entries override
inherited values. Do not silently inherit syntax from a dotenv dependency.
Resolve all references before execution; any failure prevents command launch.

Build the child environment deliberately. Never add the token, and remove known
1Password authentication variables: OP_SERVICE_ACCOUNT_TOKEN, OP_CONNECT_TOKEN,
and every variable whose name begins OP_SESSION_. Reject that same set as
file-provided keys. This list covers service-account, Connect, and CLI session
credentials; arbitrary renamed credentials cannot be detected and are outside
this guarantee. Resolve the executable using the original
PATH before applying file-provided overrides. Errors identify the operation and
line number, never the input value, SDK error payload, or resolved secret.

## Command execution

Use exec for run: no long-lived token-bearing supervisor, signal forwarding, or
output capture. Close SDK resources when supported and ensure unintended file
descriptors cannot survive exec. Release tests must inspect descriptor inheritance
on both operating systems. Do not promise secure erasure of Go strings or SDK
copies. Successful exec discards the launcher's address space.

Launcher failures before exec use the normal documented error-code contract.
Launcher-generated failures never use 125–255. Executable-not-found and
not-executable failures before exec map to missing-precondition code 3. Help
and embedded, version-stamped --skill must list the actual launcher codes.
After exec, the target owns output, exit status, and signal behavior. This is an
explicit exception to the usual subprocess-status translation convention.
Run rejects --json: management commands (doctor, enrollment, removal, and
standalone dry-run) provide single-document JSON instead. This deliberate run
exception avoids a flag whose successful output is not JSON. Before exec,
run failures are plain diagnostics on stderr. Management data goes to stdout
and diagnostics to stderr. Status alone cannot disambiguate a launcher failure
from an identically numbered target failure; offline checks do not guarantee
later execution will succeed. Dry-run must be a
separate nonexecuting path, without token retrieval or secret resolution, and
must not print values. No output masking is promised; targets may print secrets.

## Scope and evidence required

The initial implementation targets run, enrollment/removal, offline doctor,
version, and embedded --skill. One credential identity is enough initially.
No daemon, broker, custom encryption format, Windows support, or shell syntax.

Required evidence includes SDK packaging on each supported platform; Keychain
creation, locked access, and upgrades; unavailable/locked Secret Service;
protected-file checks; parser rejection cases; sentinel-value redaction tests;
all-or-nothing resolution; child environment and descriptor inspection; and
exit/signal behavior. Automated tests use fake credentials. Real-store tests
must be separately authorized and use dedicated test items.

## References

- [Official SDK setup](https://www.1password.dev/sdks)
- [Official Go SDK source](https://github.com/1Password/onepassword-sdk-go)
- [macOS ps documentation](https://raw.githubusercontent.com/apple-oss-distributions/adv_cmds/main/ps/ps.1)
- [Linux process environment documentation](https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html)
