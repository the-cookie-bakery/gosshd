# gosshd Remaining Tasks and Verification Tracker

Last updated: 2026-11-06

This document is the task register for the implementation plan in [implementation-plan.md](./implementation-plan.md). Every task is tracked by implementation status, unit-test verification, and smoke/end-to-end verification.

## 1. Status definitions

| Status | Meaning |
| --- | --- |
| Done | Implemented and covered by the listed verification |
| Partial | Implemented for the primary path, but gaps remain |
| Pending | Not implemented, or not verified enough to call complete |
| Deferred | Intentionally postponed beyond the current milestone |

## 2. Verification definitions

| Verification | Meaning |
| --- | --- |
| Unit / verification | Named Go tests, static checks, or manual inspection at package level |
| Smoke / E2E | Executed inside Podman containers by `e2e-tests` suite binaries |

Current verification commands:

```sh
go test ./...
go vet ./...
go test -tags=e2e -count=1 -timeout=30m ./e2e-tests
```

Current E2E images: Debian, Ubuntu, Fedora.

Current E2E suites: `smoke`.

## 3. Open and partial tasks

### 3.1 Configuration and compatibility

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| CFG-01 | Core `sshd_config` parser: comments, quotes, first-value semantics, common directives, unknown-keyword rejection | Done | `TestParseBasic`, `TestFirstValueWins`, `TestQuotesAndComments`, `TestUnknownKeyword`, `TestParseOption` | Smoke configs use `Port`, `ListenAddress`, `HostKey`, auth, `AuthorizedKeysFile`, and `Subsystem` |
| CFG-02 | `Include` directive with glob expansion and recursion protection | Done | Parser tests cover basic parsing; no dedicated Include test | Not covered |
| CFG-03 | `Match` blocks for User, Group, Address, LocalAddress, LocalPort, All; Match-scoped directives | Pending | No tests | Not covered; parser currently rejects Match |
| CFG-04 | `AuthorizedKeysCommand` and `AuthorizedKeysCommandUser` execution | Partial | Parsed only; startup warning emitted; no execution test | Not covered |
| CFG-05 | `AuthorizedPrincipalsCommand` and `AuthorizedPrincipalsCommandUser` execution | Pending | Not implemented | Not covered |
| CFG-06 | Full `AuthenticationMethods` composition and partial-success flows | Pending | Configurations are rejected at parse time instead of being silently ignored; composition not implemented | Not covered |
| CFG-07 | Complete semantics for accepted but ignored directives such as `Compression`, `UseDNS`, `ClientAlive*`, forwarding options | Partial | Parser accepts values; behavior is not fully implemented | Not covered |
| CFG-08 | Config validation parity: `-t`, `-T`, key permissions, include validation | Partial | `-t` and `-T` manually verified | Smoke suite starts daemon with generated config; no negative config E2E |
| CFG-09 | Match/Include E2E fixtures | Pending | None | Needed |

### 3.2 Cryptography and host keys

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| CRY-01 | Explicit modern KEX, cipher, MAC, host-key, and public-key allowlists | Done | `TestApplyDefaults`, `TestRejectWeakAlgorithms` | Smoke clients negotiate modern algorithms; negative weak-algorithm E2E pending |
| CRY-02 | Host-key and host-certificate loading with key-type restriction | Done | `TestLoadHostSigners` | Ed25519 host key used in smoke suite |
| CRY-03 | Prevent RSA host keys from advertising legacy `ssh-rsa` in worker `KEXINIT` | Partial | Monitor restricts RSA signer algorithms; worker remote signer still advertises the key type list from x/crypto | Not covered; requires an RSA host-key smoke test |
| CRY-04 | Ed448 support from RFC 8709 | Pending | x/crypto does not implement Ed448 | Not covered |
| CRY-05 | RSA minimum-size enforcement and warnings | Partial | No dedicated test | Not covered |
| CRY-06 | FIPS 140-3 mode verification | Pending | No test | Not covered |

### 3.3 Authentication, accounts, and access control

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| AUTH-01 | NSS-aware account lookup through libc `getpwnam` with file fallback | Done | `user.Lookup` fallback and container verification | Password/key sessions as real container users |
| AUTH-02 | NSS-aware shadow lookup through libc `getspnam` with file fallback | Done | Container verification | Password login in smoke suite |
| AUTH-03 | Password hash verification: yescrypt, SHA-512 crypt, SHA-256 crypt, bcrypt | Done | `go-crypt` decoder path; no dedicated vector table yet | Password login in smoke suite; hash variants need E2E cases |
| AUTH-04 | Reject locked, expired, inactive, missing, and weak-hash accounts | Partial | Account checks implemented; no dedicated unit tests | Not covered; negative auth E2E needed |
| AUTH-05 | `AllowUsers`, `DenyUsers`, `AllowGroups`, `DenyGroups`, `PermitRootLogin`, `/etc/nologin` | Partial | `TestMatchUserHost` covers pattern matching only | Not covered |
| AUTH-06 | `authorized_keys` parsing and key options (`from`, `command`, `environment`, `no-pty`, `restrict`, `expiry-time`, `no-touch-required`) | Done | `TestParseKeyOptions`, `TestParseKeyOptionsRejectsUnknown`, `TestSourceAllowed`, `TestExpandTokens` | Public-key login in smoke suite; option enforcement E2E pending |
| AUTH-07 | `authorized_keys` certificate-authority entries (`cert-authority`, `principals=`) | Pending | Option is parsed but not used by the lookup path | Not covered |
| AUTH-08 | `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`, `RevokedKeys`, host certificates | Partial | No certificate unit tests | Not covered in E2E |
| AUTH-09 | Certificate critical options and extensions parity | Partial | Supports basic `force-command`, `source-address`, `permit-pty`, `permit-user-rc` checks | Not covered |
| AUTH-10 | Password failure delay, rate limiting, and user-enumeration resistance | Pending | No tests | Not covered |
| AUTH-11 | Password length limits and timing-safe comparison audit | Partial | Crypt library comparison used; no explicit limit or test | Not covered |
| AUTH-12 | PAM backend for account/session policy and MFA | Deferred | Backend interface exists; no PAM implementation | Not covered |
| AUTH-13 | Keyboard-interactive backed by password crypt path, gated by `KbdInteractiveAuthentication` | Done | Worker callback registered only when enabled; monitor rejects disabled requests; no dedicated test | Not covered; smoke suite uses password method |
| AUTH-14 | Authentication negative test matrix: wrong password, locked, expired, denied user, denied group, bad key options | Pending | None | Needed |
| AUTH-15 | `LoginGraceTime` connection deadline covering handshake and authentication | Done | Parse validation for negative values; no deadline unit test | Not covered |

### 3.4 Privilege separation and process hardening

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| PRIV-01 | Privileged monitor, unprivileged per-connection worker, per-session launcher | Done | Manual process inspection in container | Sessions run as target user in smoke suite; E2E does not yet assert worker uid separation |
| PRIV-02 | Host private keys stay in monitor; host-key signing over RPC | Done | No dedicated unit test | Host-key handshake succeeds in smoke suite |
| PRIV-03 | Session launcher drops uid/gid/groups, applies `no_new_privs`, limits, env, chroot | Partial | No dedicated unit test | Password/key/PTY/SFTP sessions in smoke suite |
| PRIV-04 | Monitor-side verification of public-key userauth signatures | Pending | Not a security blocker: the worker's x/crypto server verifies the signature before auth succeeds. x/crypto v0.58+ provides `VerifiedPublicKeyCallback`; adoption pending, no vendored patch needed | Not covered |
| PRIV-05 | Drop monitor capabilities after startup | Pending | Not implemented | Not covered |
| PRIV-06 | Worker and session sandboxing (seccomp/Landlock) | Pending | Not implemented | Not covered |
| PRIV-07 | Bounded RPC protocol hardening and malformed-message handling | Partial | Length-limited framing and fd passing are implemented; no fuzz test | Not covered |
| PRIV-08 | Forged worker RPC tests: cannot impersonate another user or open unauthorized sessions | Pending | None | Needed |
| PRIV-09 | Chroot path ownership and component validation | Pending | Only configured chroot is applied | Not covered |
| PRIV-10 | Process cleanup and session reaping under disconnect/timeout | Partial | Basic cleanup implemented | Not covered |
| PRIV-11 | Concurrent RPC dispatch without head-of-line blocking | Done | `handleConn` dispatches packets on goroutines, session state is mutex-guarded, cleanup drains handlers; race tests pass | Concurrent-session and signal smoke regressions added |

### 3.5 Sessions, PTY, and SFTP

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| SESS-01 | `pty-req`, `shell`, `exec`, `subsystem`, `window-change`, `signal` handling | Done | No dedicated unit test | Exec and PTY execution in smoke suite |
| SESS-02 | PTY allocation, resize, and exit status propagation | Done | No dedicated unit test | PTY execution in smoke suite |
| SESS-03 | Environment filtering through `AcceptEnv`, `SetEnv`, `PermitUserEnvironment` | Done | No dedicated unit test | Not covered |
| SESS-04 | `ForceCommand`, `PermitTTY`, `MaxSessions`, `ChrootDirectory` | Partial | No dedicated unit test | Not covered |
| SESS-05 | `~/.ssh/rc` and `/etc/ssh/sshrc` execution | Pending | Parsed `PermitUserRC`; no execution | Not covered |
| SESS-06 | MOTD and last-login rendering | Pending | Parsed `PrintMotd` / `PrintLastLog`; no rendering | Not covered |
| SESS-07 | Apply terminal modes from `pty-req` | Partial | Request parsed; modes not fully applied | Not covered |
| SESS-08 | Client-alive messages and disconnect threshold | Pending | Parsed config only | Not covered |
| SESS-09 | Global request handling: keepalive, `no-more-sessions@openssh.com` | Pending | Currently uses `ssh.DiscardRequests` | Not covered |
| SESS-10 | Session max-channel and concurrent-session enforcement | Partial | `MaxSessions` is enforced in monitor | Not covered |
| SESS-11 | Session unit tests for request parsing, env filtering, exit status, and signals | Pending | None | Needed |
| SFTP-01 | In-process `internal-sftp` subsystem | Done | No dedicated unit test | SFTP write/read in smoke suite |
| SFTP-02 | Configured external subsystem execution | Partial | Implemented via `/bin/sh -c`; no test | Not covered |
| SFTP-03 | SFTP chroot and permission behavior | Partial | Relies on session chroot and OS permissions | Not covered |
| SFTP-04 | SFTP packet limits, read-only mode, and fuzz coverage | Pending | None | Not covered |

### 3.6 End-to-end test coverage and CI

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| E2E-01 | Host-side Go driver builds `gosshd` and `go test -c` suite binaries | Done | Driver compiles with `-tags=e2e` | Runs in E2E test |
| E2E-02 | Podman harness manages image build, container lifecycle, exec, logs, diagnostics, cleanup | Done | No harness unit tests | Used by every E2E run |
| E2E-03 | Debian, Ubuntu, Fedora images with SSH client, shadow tools, and runtime utilities | Done | Image builds verified | Smoke suite passes on all three |
| E2E-04 | Smoke suite: password auth, key auth, exec, PTY, internal SFTP | Done | N/A | Passing on Debian, Ubuntu, Fedora |
| E2E-05 | Authentication negative matrix: wrong password, locked/expired, denied users/groups, bad key options | Pending | None | Needed |
| E2E-06 | Certificate E2E: host cert, user cert, principals, revocation, certificate key options | Pending | None | Needed |
| E2E-07 | Config E2E: Include, Match, weak-algorithm rejection, unsupported directives | Pending | None | Needed |
| E2E-08 | Privsep E2E: monitor/worker/session uid separation, shadow/host-key access denial, forged RPC rejection | Pending | None | Needed |
| E2E-09 | OpenSSH interop E2E with real `ssh`, `scp`, `sftp`, `ssh-keygen` | Pending | None | Needed |
| E2E-10 | Forwarding rejection E2E (`direct-tcpip`, agent, X11, Unix sockets) | Pending | None | Needed |
| E2E-11 | CI workflow running unit tests, vet, and the Podman matrix | Pending | No CI configuration | Needed |
| E2E-12 | Failure artifact retention and container leak checks | Partial | Harness keeps logs/inspect data and supports `GOSSHD_E2E_KEEP=1` | No dedicated test |

### 3.7 CLI, operations, and documentation

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| OPS-01 | CLI flags: `-f`, `-t`, `-T`, `-D`, `-p`, `-h`, `-o`, `-e`, `-4`, `-6`, `-g`, `-V` | Done | Manual verification | Daemon started with `-D -f` in smoke suite |
| OPS-02 | Inetd mode (`-i`) | Pending | Returns not implemented | Not covered |
| OPS-03 | systemd socket activation | Pending | Not implemented | Not covered |
| OPS-04 | SIGHUP configuration reload | Pending | Not implemented | Not covered |
| OPS-05 | Syslog/journald integration and log levels | Partial | Uses standard logger; parsed `LogLevel` not fully applied | Not covered |
| OPS-06 | PID file lifecycle | Done | Manual code inspection | Not covered |
| OPS-07 | Man page and example configuration | Pending | README exists | Not covered |
| OPS-08 | Threat model and security review document | Pending | Not written | Not covered |
| DOC-01 | Implementation plan document | Done | `docs/implementation-plan.md` | N/A |
| DOC-02 | Remaining task and verification tracker | Done | This document | N/A |

## 4. Completed baseline

The following areas are implemented and have at least smoke or unit verification:

| Area | Evidence |
| --- | --- |
| RFC references | `specifications/rfc4253.txt`, `rfc6668`, `rfc8268`, `rfc8308`, `rfc8332`, `rfc8709`, `rfc8758`, `rfc9142` |
| Build | `CGO_ENABLED=0 go build ./cmd/gosshd` |
| Unit tests | `internal/config`, `internal/crypto`, `internal/auth` |
| Static check | `go vet ./...` passes |
| E2E harness | `e2e-tests/harness` builds test binaries and manages Podman containers |
| E2E matrix | Debian, Ubuntu, Fedora smoke suites pass |
| Password auth | Yescrypt/SHA-crypt/bcrypt path through NSS shadow lookup |
| Public-key auth | `authorized_keys`, source restrictions, forced commands, key options |
| Privsep | Monitor, unprivileged worker, target-user session launcher |
| Session | PTY, exec, shell, environment, signals, resize, exit status |
| SFTP | Internal SFTP write/read |
| Crypto policy | Explicit modern allowlists and weak-algorithm rejection |

## 5. Suggested next milestones

### Milestone A: security-critical corrections

1. Adopt `VerifiedPublicKeyCallback` for signature-aware monitor authorization (no vendored patch required).
2. Add monitor capability dropping and worker/session sandboxing.
3. Add forged-RPC and worker-isolation tests.
4. Add public-key negative tests and certificate E2E coverage.

### Milestone B: configuration compatibility

1. Implement Match parsing and evaluation.
2. Implement `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand`.
3. Add config E2E fixtures for Include, Match, weak algorithms, and unsupported directives.

### Milestone C: operational readiness

1. Implement client-alive, keepalive, `no-more-sessions`, and session request parity.
2. Add rc-file, MOTD, and last-login behavior.
3. Add systemd socket activation, inetd mode, SIGHUP reload, and syslog integration.
4. Add CI, fuzzing, race tests, `staticcheck`, and `govulncheck`.

### Milestone D: optional PAM backend

1. Implement the `PasswordVerifier` PAM backend behind the existing interface.
2. Add PAM account and session management.
3. Add PAM-specific E2E coverage for MFA, account policy, and session modules.
