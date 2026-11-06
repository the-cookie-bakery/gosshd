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
make ci
go test -tags=e2e -count=1 -timeout=30m ./e2e-tests
```

Current E2E images: Debian, Ubuntu, Fedora.

Current E2E suites: `smoke`, `auth`, `privsep`, `config`, `cert`, `interop`, `sftp`, `daemon`.

## 3. Open and partial tasks

### 3.1 Configuration and compatibility

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| CFG-01 | Core `sshd_config` parser: comments, quotes, first-value semantics, common directives, unknown-keyword rejection | Done | `TestParseBasic`, `TestFirstValueWins`, `TestQuotesAndComments`, `TestUnknownKeyword`, `TestParseOption` | Smoke configs use `Port`, `ListenAddress`, `HostKey`, auth, `AuthorizedKeysFile`, and `Subsystem` |
| CFG-02 | `Include` directive with glob expansion and recursion protection | Done | Parser tests cover basic parsing; no dedicated Include test | Not covered |
| CFG-03 | `Match` blocks for User, Group, Address, LocalAddress, LocalPort, All; Match-scoped directives | Done | Parser and `Config.Resolve` tests cover criteria, negation, global precedence, first-value-wins, and supported directives | `auth` suite covers Match User/Address auth and session policy |
| CFG-04 | `AuthorizedKeysCommand` and `AuthorizedKeysCommandUser` execution | Done | Root-owned absolute command validation, argv/token expansion, privilege drop, timeout/output limits, and reader-based key parsing; unit tests | `auth` suite logs in via command-provided keys |
| CFG-05 | `AuthorizedPrincipalsCommand` and `AuthorizedPrincipalsCommandUser` execution | Done | Command execution and principal parsing share the validated command path; unit tests | `cert` suite logs in via command-provided principals |
| CFG-06 | Full `AuthenticationMethods` composition and partial-success flows | Done | Parsed alternatives, startup validation, per-connection auth-progress state machine, and `PartialSuccessError` callbacks; unit tests cover completion/partial/wrong-order cases | `auth` suite covers publickey+password success, single-factor failure, and wrong second factor |
| CFG-07 | Complete semantics for accepted but ignored directives such as `Compression`, `UseDNS`, `ClientAlive*`, forwarding options | Partial | `ClientAlive*`, `TCPKeepAlive`, `MaxStartups`, and `Banner` are applied; `Compression yes` or `delayed` and `UseDNS yes` are rejected; forwarding options remain acknowledged only because forwarding is disabled | `interop` exercises client-alive and TCP keepalive paths |
| CFG-08 | Config validation parity: `-t`, `-T`, key permissions, include validation | Done | `-t` validates command paths/users and host-key permissions; `-T` emits lowercase keyword/value text; repeated `-o` and `keyword=value` forms | `config` suite covers `-T` defaults, overrides, and negative host-key permission cases |
| CFG-09 | Match/Include E2E fixtures | Done | `config`, `auth`, and existing Include fixtures | Passing |
| CFG-10 | `Banner` file delivery before authentication | Done | `TestLoadBanner`; banner parsing test | `auth` suite verifies banner delivery |
| CFG-11 | Reject unsupported `UseDNS yes` and `Compression yes` or `delayed` | Done | `TestUseDNSAndCompressionTruthfulness` | `config` suite rejects both settings |
| CFG-12 | Full `MaxStartups start:rate:full` pre-authentication accounting | Done | `TestMaxStartupsParsing`, `TestAcceptStartupBoundaries`, `TestAcceptStartupRandomDrop` | `config` suite accepts triples and rejects invalid ordering |
| CFG-13 | Truthful `RekeyLimit` time handling and rejection of unsupported authentication enables | Done | `TestRekeyLimitTruthfulness`, `TestUnsupportedAuthMethodsRejected` | `config` suite rejects time components and unsupported `yes` values |

### 3.2 Cryptography and host keys

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| CRY-01 | Explicit modern KEX, cipher, MAC, host-key, and public-key allowlists | Done | `TestApplyDefaults`, `TestRejectWeakAlgorithms` | `config` suite rejects weak KEX, cipher, MAC, host-key, and public-key algorithms; smoke clients negotiate modern algorithms |
| CRY-02 | Host-key and host-certificate loading with key-type restriction | Done | `TestLoadHostSigners` | Ed25519 host key used in smoke suite |
| CRY-03 | Prevent RSA host keys from advertising legacy `ssh-rsa` in worker `KEXINIT` | Done | Monitor sends per-key algorithm restrictions; worker remote signer implements `MultiAlgorithmSigner` | `auth` suite verifies `rsa-sha2-*` negotiation and rejects `ssh-rsa`-only clients |
| CRY-04 | Ed448 support from RFC 8709 | Pending | x/crypto does not implement Ed448 | Not covered |
| CRY-05 | RSA minimum-size enforcement and warnings | Done | `RequiredRSASize` defaults to 2048; enforced for host, user, and certificate keys; `TestLoadHostSignersRSAMinimum`, `TestCheckRSASize` | Not covered |
| CRY-06 | FIPS 140-3 mode verification | Pending | No test | Not covered |
| CRY-07 | `CASignatureAlgorithms` validation and enforcement for user certificate CA signatures | Done | `TestCASignatureAlgorithmDefaultsAndValidation`, `TestCASignatureAlgorithmsEnforced` | `cert` suite verifies allowed and rejected CA algorithms |

### 3.3 Authentication, accounts, and access control

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| AUTH-01 | NSS-aware account lookup through `getent passwd` with a short cache and file fallback | Done | Parser and cache tests; container verification | Password/key sessions as real container users |
| AUTH-02 | NSS-aware shadow lookup through `getent shadow` with a short cache and file fallback | Done | Parser and cache tests; container verification | Password login in smoke suite |
| AUTH-03 | Password hash verification: yescrypt, SHA-512 crypt, SHA-256 crypt, bcrypt | Done | `go-crypt` decoder path; no dedicated unit vector table | `auth` suite `TestPasswordHashVariants` covers `$5$`, `$6$`, `$2b$`, and `$y$` logins |
| AUTH-04 | Reject locked, expired, inactive, missing, and weak-hash accounts | Done | Account checks implemented; auth suite covers locked, expired, unknown, and wrong-password cases | `auth` suite covers locked, expired, and unknown accounts |
| AUTH-05 | `AllowUsers`, `DenyUsers`, `AllowGroups`, `DenyGroups`, `PermitRootLogin`, `/etc/nologin` | Done | `TestMatchUserHost` covers pattern matching | `auth` suite covers Allow/Deny users and groups, PermitRootLogin, and `/etc/nologin` |
| AUTH-06 | `authorized_keys` parsing and key options (`from`, `command`, `environment`, `no-pty`, `restrict`, `expiry-time`, `no-touch-required`) | Done | `TestParseKeyOptions`, `TestParseKeyOptionsRejectsUnknown`, `TestSourceAllowed`, `TestExpandTokens` | `auth` suite covers `from`, forced command, `no-pty`, `environment`, `restrict`, `no-user-rc`, and `expiry-time` |
| AUTH-07 | `authorized_keys` certificate-authority entries (`cert-authority`, `principals=`) | Done | CA lines are matched against the certificate signing key with principal restrictions; `TestAuthorizedKeysCertAuthority` | `cert` suite covers success and wrong-principal rejection |
| AUTH-08 | `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`, `RevokedKeys`, host certificates | Done | Certificate paths exercised by the `cert` suite | `cert` suite covers trusted CA, principals file, revocation, and host certificates |
| AUTH-09 | Certificate critical options and extensions parity | Done | Supports `force-command`, `source-address`, `permit-pty`, `permit-user-rc`, and records forwarding extension permissions | `cert` suite verifies permit-pty acceptance and default denial |
| AUTH-10 | Password failure delay, rate limiting, and user-enumeration resistance | Done | Dummy-hash verification, jittered failure delay, and fixed per-IP limiter; `TestAuthLimiterDelay` | Negative auth attempts exercise the paths; timing itself is not asserted |
| AUTH-11 | Password length limits and timing-safe comparison audit | Done | 1024-byte limit enforced before lookup; `TestPasswordLengthLimit`; crypt library comparison | Not covered |
| AUTH-12 | PAM backend for account/session policy and MFA | Deferred | Backend interface exists; no PAM implementation | Not covered |
| AUTH-13 | Keyboard-interactive backed by password crypt path, gated by `KbdInteractiveAuthentication` | Done | Worker callback registered only when enabled; monitor rejects disabled requests | `auth` suite verifies successful keyboard-interactive login and disabled gating |
| AUTH-14 | Authentication negative test matrix: wrong password, locked, expired, denied user, denied group, bad key options | Done | New `auth` suite | Passing on Debian; matrix runs on all images |
| AUTH-15 | `LoginGraceTime` connection deadline covering handshake and authentication | Done | Parse validation for negative values | `daemon` suite `TestLoginGraceTime` verifies the connection is closed |

### 3.4 Privilege separation and process hardening

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| PRIV-01 | Privileged monitor, unprivileged per-connection worker, per-session launcher | Done | Manual process inspection in container | Sessions run as target user in smoke suite; E2E does not yet assert worker uid separation |
| PRIV-02 | Host private keys stay in monitor; host-key signing over RPC | Done | No dedicated unit test | Host-key handshake succeeds in smoke suite |
| PRIV-03 | Session launcher drops uid/gid/groups, applies `no_new_privs`, limits, env, chroot | Done | Session sandbox tests plus launcher unit tests | `privsep` and `sftp` suites verify uid, chroot, and sandbox behavior |
| PRIV-04 | Monitor-side verification of public-key userauth signatures | Done | `VerifiedPublicKeyCallback` re-confirms authorization after signature proof; no vendored patch | Covered indirectly by key and certificate suites |
| PRIV-05 | Drop monitor capabilities after startup | Done | `internal/privsep/caps.go` drops the bounding set and effective/permitted set across all Go threads; fail-closed when root | `privsep` suite asserts monitor `CapEff`/`CapBnd` and per-thread consistency |
| PRIV-06 | Worker and session sandboxing (seccomp/Landlock) | Done | Worker seccomp deny-list with `TSYNC`; session Landlock write sandbox with fail-closed startup and ABI mask tests | `auth` suite verifies allowed/denied writes; all suites pass |
| PRIV-07 | Bounded RPC protocol hardening and malformed-message handling | Done | Length-limited framing, fd passing, and `FuzzPacketDecode`; config and authorized_keys fuzz targets | Not covered |
| PRIV-08 | Forged worker RPC tests: cannot impersonate another user or open unauthorized sessions | Done | Socket-level tests cover unauthenticated `session_open`, unknown-session operations, malformed payloads, and per-connection state isolation | Worker isolation and capability assertions covered by `privsep` suite |
| PRIV-09 | Chroot path ownership and component validation | Done | `resolveChroot` expands tokens and rejects relative, missing, symlinked, non-root, or writable components; `chroot_test.go` | Not covered; unit tests cover validation |
| PRIV-10 | Process cleanup and session reaping under disconnect/timeout | Done | `TestDisconnectCleanup` and `TestLoginGraceTime` | `privsep` and `daemon` suites verify reaping and timeout |
| PRIV-11 | Concurrent RPC dispatch without head-of-line blocking | Done | `handleConn` dispatches packets on goroutines, session state is mutex-guarded, cleanup drains handlers; race tests pass | Concurrent-session and signal smoke regressions added |

### 3.5 Sessions, PTY, and SFTP

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| SESS-01 | `pty-req`, `shell`, `exec`, `subsystem`, `window-change`, `signal` handling | Done | No dedicated unit test | Exec and PTY execution in smoke suite |
| SESS-02 | PTY allocation, resize, and exit status propagation | Done | No dedicated unit test | PTY execution in smoke suite |
| SESS-03 | Environment filtering through `AcceptEnv`, `SetEnv`, `PermitUserEnvironment` | Done | No dedicated unit test | Not covered |
| SESS-04 | `ForceCommand`, `PermitTTY`, `MaxSessions`, `ChrootDirectory` | Done | `auth` suite covers ForceCommand, PermitTTY, and MaxSessions | `sftp` suite covers chrooted sessions |
| SESS-05 | `~/.ssh/rc` and `/etc/ssh/sshrc` execution | Done | Executed before shell/command with `SSH_CLIENT`/`SSH_CONNECTION`; `TestUserRC` covers enabled/disabled | `auth` suite verifies rc execution and `PermitUserRC no` |
| SESS-06 | MOTD and last-login rendering | Done | `readMotd`, `readLastLog`, and `logininfo` unit tests | `auth` suite verifies MOTD and last-login output |
| SESS-07 | Apply terminal modes from `pty-req` | Done | RFC 4254 mode decoder and termios application with unit tests | `auth` suite uses `stty -a` to verify ECHO changes |
| SESS-08 | Client-alive messages and disconnect threshold | Done | Keepalive state machine unit tests; liveness treats any reply as alive | `interop` suite keeps a session alive across the interval |
| SESS-09 | Global request handling: keepalive, `no-more-sessions@openssh.com` | Done | Dedicated handler replies to keepalive, latches no-more-sessions, rejects forwarding globals | `interop` suite covers no-more-sessions and forwarding rejection |
| SESS-10 | Session max-channel and concurrent-session enforcement | Done | `MaxSessions` enforced in monitor | `auth` suite covers the limit |
| SESS-11 | Session unit tests for request parsing, env filtering, exit status, and signals | Done | `TestBuildEnv`, `TestApplyTerminalMode`, `TestReadMotd`, `TestReadLastLog`, `TestSignalNumber` | Exit status and signals covered by `smoke` E2E |
| SFTP-01 | In-process `internal-sftp` subsystem | Done | No dedicated unit test | SFTP write/read in smoke suite |
| SFTP-02 | Configured external subsystem execution | Done | `sftp` suite runs a configured external subsystem | Passing |
| SFTP-03 | SFTP chroot and permission behavior | Done | `sftp` suite writes through chrooted internal SFTP | Passing |
| SFTP-04 | SFTP packet limits, read-only mode, and fuzz coverage | Done | `internal-sftp -R`/`-d` parsing, read-only E2E, deeper option fuzz seeds; pkg/sftp enforces a 32 KiB packet limit | Read-only and chroot paths covered |

### 3.6 End-to-end test coverage

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| E2E-01 | Host-side Go driver builds `gosshd` and `go test -c` suite binaries | Done | Driver compiles with `-tags=e2e` | Runs in E2E test |
| E2E-02 | Podman harness manages image build, container lifecycle, exec, logs, diagnostics, cleanup | Done | No harness unit tests | Used by every E2E run |
| E2E-03 | Debian, Ubuntu, Fedora images with SSH client, shadow tools, and runtime utilities | Done | Image builds verified | Smoke suite passes on all three |
| E2E-04 | Smoke suite: password auth, key auth, exec, PTY, internal SFTP | Done | N/A | Passing on Debian, Ubuntu, Fedora |
| E2E-05 | Authentication negative matrix: wrong password, locked/expired, denied users/groups, bad key options | Done | New `auth` suite | Passing |
| E2E-06 | Certificate E2E: host cert, user cert, principals, revocation, certificate key options | Done | New `cert` suite | Passing |
| E2E-07 | Config E2E: Include, Match, weak-algorithm rejection, unsupported directives | Done | `config` suite covers Include/recursion, Match, weak algorithms, unknown keywords, valid/invalid `AuthenticationMethods`, and `-T` | Passing |
| E2E-08 | Privsep E2E: monitor/worker/session uid separation, shadow/host-key access denial, forged RPC rejection | Done | `privsep` suite asserts uid separation, monitor capability reduction, empty worker capabilities, and `setpriv` access denial for shadow/host keys | Passing |
| E2E-09 | OpenSSH interop E2E with real `ssh`, `scp`, `sftp`, `ssh-keygen` | Done | New `interop` suite | `ssh`, `scp`, and `sftp` pass |
| E2E-10 | Forwarding rejection E2E (`direct-tcpip`, agent, X11, Unix sockets) | Done | `interop` suite rejects direct-tcpip, remote forward, agent, and X11 requests | Passing |
| E2E-11 | Configuration truthfulness negative E2E: `UseDNS`, `Compression`, weak CA algorithms, invalid `MaxStartups` | Done | N/A | `config` and `cert` suites cover the matrix |
| E2E-12 | Failure artifact retention and container leak checks | Done | `TestResolveArtifactsDir`, `TestCloseRemovesContainer` | `Close` verifies removal and `GOSSHD_E2E_KEEP=1` retains artifacts under `e2e-tests/.artifacts` |

### 3.7 CLI, operations, and documentation

| ID | Task | Implementation status | Unit test / verification | Smoke test / E2E test |
| --- | --- | --- | --- | --- |
| OPS-01 | CLI flags: `-f`, `-t`, `-T`, `-D`, `-p`, `-h`, `-o`, `-e`, `-4`, `-6`, `-g`, `-V` | Done | Manual verification | Daemon started with `-D -f` in smoke suite |
| OPS-02 | Inetd mode (`-i`) | Done | `serveInetd` uses stdin as the connection; `daemon` suite exercises it | Passing |
| OPS-03 | systemd socket activation | Done | `LISTEN_PID`/`LISTEN_FDS` adoption; `TestSystemdListenersInactive`, `TestSystemdListenersInvalidEnvironment` | `daemon` suite `TestSystemdSocketActivation` serves a session from an inherited listener |
| OPS-04 | SIGHUP configuration reload | Done | Policy reload with listener/host-key change rejection; `reloadCompatible` unit tests | `daemon` suite reloads ForceCommand and rejects listener changes |
| OPS-05 | Syslog/journald integration and log levels | Done | Leveled logger with syslog fallback; `TestLevelFiltering` | `daemon` suite `TestSyslogLogging` verifies `/dev/log` delivery |
| OPS-06 | PID file lifecycle | Done | Manual code inspection | Not covered |
| OPS-07 | Man page and example configuration | Done | `docs/gosshd.8`, `docs/sshd_config.example`, README links | N/A |
| OPS-08 | Threat model and security review document | Done | `docs/threat-model.md` covers assets, trust boundaries, attacker models, controls, residual risks, and non-goals | N/A |
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

## 5. Remaining work

### Milestone G: optional PAM backend

1. Implement the `PasswordVerifier` PAM backend behind the existing interface.
2. Add PAM account and session management.
3. Add PAM-specific E2E coverage for MFA, account policy, and session modules.

## 6. Priority mapping

The v1 definition of done refers to P0/P1 work. Status rows do not carry a priority column; the mapping below is authoritative.

### P0: release blockers

`AUTH-10`, `AUTH-11`, `AUTH-14`, `CFG-03`, `CFG-06`, `CRY-01`, `CRY-02`, `PRIV-05`, `PRIV-06`, `PRIV-08`, `PRIV-09`, `SESS-08`, `SESS-09`, `OPS-08`, `E2E-09`, `E2E-10`, `E2E-11`

### P1: v1 scope

`AUTH-04`, `AUTH-05`, `AUTH-07`, `AUTH-08`, `AUTH-09`, `CFG-04`, `CFG-05`, `CFG-07`, `CFG-08`, `CFG-09`, `CFG-10`, `CFG-11`, `CFG-12`, `CFG-13`, `CRY-03`, `CRY-05`, `CRY-07`, `PRIV-04`, `PRIV-07`, `PRIV-10`, `SESS-04`, `SESS-05`, `SESS-06`, `SESS-07`, `SESS-10`, `SESS-11`, `SFTP-02`, `SFTP-03`, `SFTP-04`, `E2E-07`, `E2E-08`, `E2E-11`, `E2E-12`, `OPS-02`, `OPS-03`, `OPS-04`, `OPS-05`, `OPS-07`

### P2 and deferred

`AUTH-12` (PAM, deferred), `CRY-04` (Ed448, blocked upstream), `CRY-06` (FIPS, depends on Go FIPS support). All remaining unlisted items are P2.
