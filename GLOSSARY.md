# Glossary

- **Service account:** A 1Password identity for automated access to selected vaults.
- **Service-account token:** The credential authenticating that identity.
- **Vault:** A collection of items stored in 1Password with shared access rules.
- **Secret reference:** An `op://vault/item/field` identifier, not the secret itself.
- **SDK:** A software development kit; here, the official Go library for 1Password.
- **Keychain:** The macOS credential storage service.
- **Secret Service:** The Linux desktop protocol for storing credentials through a session service.
- **GNOME Keyring:** A Linux credential-store implementation of Secret Service. Its login keyring is an encrypted collection normally unlocked during desktop login.
- **SSH:** Secure Shell, used to open a terminal session on another machine. SSH login does not necessarily unlock a desktop keyring.
- **Headless:** Running without an interactive desktop session.
- **Environment:** Named string values passed to a program when it starts.
- **exec:** A Unix operation that replaces the current program with another.
- **CLI:** A command-line interface.
- **cgo:** Go's interface to native system libraries, used here for macOS Keychain.
- **D-Bus:** A local messaging system used to communicate with Linux Secret Service.
- **WebAssembly:** A portable executable format used internally by the 1Password SDK.
- **File descriptor:** A process-local handle for an open file, socket, or pipe.
- **Close-on-exec:** A flag that closes an open handle when a process replaces itself.
