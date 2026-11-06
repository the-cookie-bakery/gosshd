# gosshd Implementation Plan

Last updated: 2026-11-06

## 1. Purpose

gosshd is a Linux SSH server built on `golang.org/x/crypto/ssh`. The project targets a small feature surface, a modern cryptographic baseline, and compatibility with the parts of the standard OpenSSH configuration and authentication model needed for a practical SSHd replacement.

The detailed task register, including implementation status and verification state, lives in [remaining-tasks.md](./remaining-tasks.md). The security assumptions, trust boundaries, and residual risks are documented in [threat-model.md](./threat-model.md).

## 2. Scope decisions

| Area | Decision |
| --- | --- |
| Operating system | Linux only for v1, with OS-specific code isolated for later ports |
| Go version | Go 1.27+ |
| Build mode | `CGO_ENABLED=0` |
| Password auth | crypt-only in v1: NSS-aware shadow lookup through `getent` plus pure-Go yescrypt/SHA-crypt/bcrypt verification |
| PAM | Not in v1; a password-backend interface is present so PAM can be added later |
| Public-key auth | OpenSSH `authorized_keys`, key options, user certificates, host certificates |
| SFTP | In-process `internal-sftp` plus configured external subsystems |
| Forwarding | TCP, agent, X11, and Unix-socket forwarding are rejected and not advertised |
| Privilege model | Privileged monitor, unprivileged per-connection workers, per-session launchers |
| Host-key protection | Host private keys stay in the monitor; workers request signatures over RPC |
| Modern crypto | Explicit allowlists; weak KEX, ciphers, MACs, RSA/SHA-1, DSA, and RC4 are rejected |
| E2E testing | Host-side Go driver builds `go test -c` suite binaries and runs them in Podman containers |
| Default image matrix | Debian, Ubuntu, Fedora |

## 3. Target architecture

```text
gosshd monitor (root, limited capabilities planned)
├── owns listeners, config, host private keys, host certificates
├── reads shadow data through libc/NSS
├── validates accounts, authorized_keys, certificates, and access policy
├── verifies passwords and authorizes public keys
├── signs host-key handshake data
├── spawns unprivileged network workers
└── spawns per-session launchers that drop to the target user

unprivileged worker (one per TCP connection)
├── runs x/crypto/ssh transport, key exchange, channels, and session requests
├── never has root, shadow access, host private keys, or authorized_keys access
├── forwards authentication decisions to the monitor over an internal RPC socket
└── relays session channel data between the SSH client and the session process

session launcher (root at exec, drops immediately)
├── applies chroot, resource limits, umask, and no_new_privs
├── applies supplementary groups, gid, and uid
├── sets environment and working directory
├── executes the user's shell/command or runs internal SFTP
└── never handles network traffic
```

### Internal RPC

The monitor and worker communicate over a Unix socketpair using bounded, length-framed messages. File descriptors are transferred with `SCM_RIGHTS`.

Planned/required RPCs:

| RPC | Purpose |
| --- | --- |
| `sign` | Monitor signs host-key handshake data |
| `password` | Monitor verifies password credentials |
| `keyboard` | Monitor verifies keyboard-interactive password credentials |
| `pubkey_authorize` | Monitor checks account, key file, certificate, revocation, and options |
| `session_open` | Monitor authorizes and starts a session, returning PTY/pipe descriptors |
| `session_resize` | Monitor resizes the PTY |
| `session_signal` | Monitor forwards a signal to the session process |
| `session_wait` | Monitor reaps the session and returns exit status |
| `session_close` | Monitor terminates and cleans up a session |

The worker treats monitor RPC responses as authoritative. The monitor treats worker input as untrusted and derives session identity from its own authenticated connection state. Packets for a connection are dispatched concurrently, so long-running `session_wait` calls do not block resize, signal, close, or other sessions.

## 4. Cryptographic baseline

### Key exchange

Enabled by default when supported:

```text
mlkem768x25519-sha256
curve25519-sha256
ecdh-sha2-nistp256
ecdh-sha2-nistp384
ecdh-sha2-nistp521
diffie-hellman-group16-sha512
diffie-hellman-group14-sha256
```

Rejected:

```text
diffie-hellman-group1-sha1
diffie-hellman-group14-sha1
diffie-hellman-group-exchange-sha1
```

### Ciphers

```text
chacha20-poly1305@openssh.com
aes256-gcm@openssh.com
aes128-gcm@openssh.com
aes256-ctr
aes192-ctr
aes128-ctr
```

Rejected: CBC modes, 3DES, RC4/arcfour, and `none`.

### MACs

```text
hmac-sha2-512-etm@openssh.com
hmac-sha2-256-etm@openssh.com
hmac-sha2-512
hmac-sha2-256
```

Rejected: all SHA-1 and MD5 HMACs, and `none`.

### Host and user keys

Allowed:

```text
ssh-ed25519
ecdsa-sha2-nistp256
ecdsa-sha2-nistp384
ecdsa-sha2-nistp521
rsa-sha2-512
rsa-sha2-256
```

Rejected: `ssh-rsa` with SHA-1, `ssh-dss`, and disallowed RSA key sizes. RFC 8709 Ed448 support is not available in the current x/crypto baseline and remains a known limitation.

## 5. Authentication and account model

### Password verification

1. Resolve the account through `getent passwd` (NSS-aware) with a short cache and a file fallback.
2. Resolve the shadow entry through `getent shadow` (NSS-aware) with a short cache and a file fallback.
3. Reject locked, expired, inactive, or missing accounts.
4. Verify supported hashes:
   - yescrypt (`$y$`)
   - SHA-512 crypt (`$6$`)
   - SHA-256 crypt (`$5$`)
   - bcrypt (`$2b$`, `$2a$`, `$2y$`)
5. Reject DES, MD5-crypt, SHA-1 crypt, plaintext, and unknown formats.
6. Allow empty passwords only when `PermitEmptyPasswords yes`.
7. Zero password buffers after use.

### Account and access policy

Implemented checks include:

- `AllowUsers` / `DenyUsers`, including `user@host` and CIDR host patterns
- `AllowGroups` / `DenyGroups`
- `PermitRootLogin`
- `/etc/nologin` for non-root users
- password expiry, account expiry, and inactivity fields
- `MaxAuthTries`, `MaxSessions`, `MaxStartups` connection cap
- `LoginGraceTime` via a connection deadline covering the handshake and authentication
- keyboard-interactive gated by `KbdInteractiveAuthentication`
- password length cap, dummy-hash verification for unknown users, jittered failure delay, and a fixed per-IP failure limiter
- `RequiredRSASize` (default 2048) for host, user, and certificate RSA keys

### Public-key authentication

1. Worker receives the public-key query or signed request.
2. Monitor validates the account, key file, certificate chain, principals, revocation, and key options.
3. Worker verifies the userauth signature using x/crypto.
4. Monitor returns effective permissions: forced command, source restriction, environment restrictions, no-PTY, no-user-rc, and similar options.

The worker's x/crypto server verifies the userauth signature before authentication succeeds. gosshd also uses `VerifiedPublicKeyCallback` to re-confirm authorization after signature proof, so no vendored x/crypto patch is required. `AuthenticationMethods` composition uses `PartialSuccessError` with per-connection auth-progress tracking.

## 6. Configuration compatibility target

The parser currently supports:

- comments, blank lines, quoted arguments, and first-value-wins semantics
- `Include` with glob expansion and recursion protection
- common network, host-key, crypto, authentication, access, session, subsystem, and logging directives, including `RequiredRSASize`, `AuthenticationMethods`, `Match`, and authorized-command execution
- explicit rejection of unknown keywords
- explicit rejection of directives that try to re-enable weak cryptography
- host-key permission validation (`-t`/startup); `-T` currently emits JSON rather than OpenSSH text

Not yet implemented:

- complete OpenSSH directive semantics for every accepted keyword
- full certificate option/extension parity

Directives that relate to forwarding are parsed and acknowledged but forwarding remains disabled by design.

## 7. Session and SFTP model

The session layer supports:

- `pty-req`, `env`, `shell`, `exec`, `subsystem`, `window-change`, and `signal`
- PTY allocation, terminal sizing, terminal mode application, stdout/stderr handling, and exit status
- client-alive keepalives, TCP keepalive, `keepalive@openssh.com`, and `no-more-sessions@openssh.com`
- environment filtering through `AcceptEnv`, `SetEnv`, and `PermitUserEnvironment`
- `~/.ssh/rc` / `/etc/ssh/sshrc`, MOTD, last-login rendering, and `SSH_CLIENT`/`SSH_CONNECTION`
- forced commands from configuration, authorized_keys, and certificates
- `ForceCommand`, `PermitTTY`, `MaxSessions`, `ChrootDirectory`
- internal SFTP through `github.com/pkg/sftp`, including read-only mode (`-R`) and start directory (`-d`)
- configured external subsystems

Not yet implemented:

- SFTP resource limits and deeper fuzz coverage

## 8. Privilege separation model

Implemented:

- monitor listens, authenticates, signs host keys, and spawns workers/sessions
- worker drops to the `nobody` account when the monitor runs as root
- session launcher drops to the target uid/gid and supplementary groups
- session launcher applies `no_new_privs`, resource limits, umask, chroot, environment, and exec
- the monitor owns remote/local connection identity; worker-supplied addresses are diagnostic only
- the monitor drops unnecessary capabilities across all runtime threads after startup (fail-closed)
- workers install a seccomp deny-list with `TSYNC` before serving SSH
- host private keys are not loaded by workers
- worker RPC protocol bounds message size and uses fd passing

Remaining hardening:

- add session-process Landlock/seccomp policy (worker sandbox is done)
- extend fuzzing to certificate parsing and deeper SFTP paths

## 9. End-to-end test harness

Directory layout:

```text
e2e-tests/
├── e2e_test.go
├── harness/
├── images/{debian,ubuntu,fedora}/Containerfile
├── suites/{smoke,auth,privsep,config,cert,interop}/
└── testdata/
```

The host-side driver:

1. Builds `gosshd` with `CGO_ENABLED=0`.
2. Builds suite binaries with `go test -c -tags=e2e`.
3. Ensures the requested Podman images exist.
4. Starts an ephemeral container per `(suite, image)` pair.
5. Runs the suite binary inside the container with `podman exec`.
6. Collects logs and diagnostics on failure.
7. Removes containers unless `GOSSHD_E2E_KEEP=1`.

Suites verify:

- `smoke`: password/public-key auth, exec, PTY, concurrent sessions, signals, internal SFTP
- `auth`: wrong password, locked/expired/unknown accounts, allow/deny users, authorized_keys options, disabled auth methods, keyboard-interactive gating
- `privsep`: worker and session uid separation
- `config`: Include/recursion, weak algorithms, unknown keywords, valid/invalid `AuthenticationMethods`, `-T` defaults
- `cert`: trusted user CA, principals file, revocation, `cert-authority` in `authorized_keys`, certificate force-command, host certificates
- `interop`: real `ssh`/`scp`/`sftp`, exit status, PTY, client-alive longevity, `no-more-sessions`, and forwarding rejection
- Debian, Ubuntu, and Fedora containers

## 10. Phase plan and status

Status values are defined in [remaining-tasks.md](./remaining-tasks.md).

| Phase | Scope | Implementation status | Unit verification | Smoke / E2E verification |
| --- | --- | --- | --- | --- |
| 1 | RFC references, module skeleton, repository layout | Done | Build succeeds | N/A |
| 2 | Config parser, crypto policy, host-key loading | Done for core directives, including Match | `internal/config`, `internal/crypto` tests | Config exercised by smoke/auth/config suites |
| 3 | NSS/shadow/crypt authentication and access policy | Done for crypt-only path | `internal/auth` tests; crypt path exercised in container | Password login in smoke suite |
| 4 | authorized_keys, key options, certificates | Partial | Authorized-key option tests | Public-key login in smoke suite; certificates not yet in E2E |
| 5 | Privsep monitor/worker/session launcher | Partial | No dedicated unit tests yet | Password/key/PTY/SFTP sessions in smoke suite |
| 6 | PTY, shell, exec, environment, signals, exit status | Done for core paths | No dedicated PTY unit tests | PTY and exec in smoke suite |
| 7 | Internal SFTP and external subsystems | Partial | No dedicated SFTP unit tests | SFTP write/read in smoke suite |
| 8 | Podman harness and container images | Done | Harness has no unit tests | Debian/Ubuntu/Fedora smoke matrix |
| 9 | Hardening, fuzzing, CI, operations | Pending | `go vet` passes; fuzz/race/govulncheck pending | CI workflow pending |

## 11. Definition of done for v1

A v1 release is ready when:

- all open tasks marked `P0` or `P1` in [remaining-tasks.md](./remaining-tasks.md) are complete
- `go test ./...`, `go vet ./...`, `staticcheck`, and `govulncheck` pass
- the full e2e matrix passes on Debian, Ubuntu, and Fedora
- config compatibility tests cover Match, Include, first-value semantics, and weak-algorithm rejection
- auth tests cover password, public key, certificates, locked/expired accounts, and access controls
- privsep tests verify worker isolation and monitor-side public-key verification
- session tests cover PTY, exec, environment filtering, signals, exit status, chroot, and MaxSessions
- SFTP tests cover internal-sftp, external subsystems, chroot, permissions, and limits
- a documented threat model and security review are complete
