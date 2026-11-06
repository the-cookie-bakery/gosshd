# gosshd Threat Model

Last updated: 2026-11-06

## 1. Scope

This document covers the v1 Linux SSH server implemented by this repository. It describes the assets the server protects, the trust boundaries between its processes, the attacker capabilities considered, and the controls that mitigate them. It also records residual risks and explicit non-goals.

The SSH transport, key exchange, channel multiplexing, and userauth signature verification are provided by `golang.org/x/crypto/ssh`. This model treats that library as part of the attack surface rather than as a trusted component.

## 2. Assets

| Asset | Why it matters |
| --- | --- |
| Host private keys and host certificates | Impersonation of the server, session decryption within a connection |
| `/etc/shadow` hashes and account metadata | Offline password cracking, account discovery |
| User `authorized_keys` and certificate authorities | Unauthorized login |
| User files reachable by a session | Data confidentiality and integrity |
| Session processes and PTYs | Command execution as the target user |
| Configuration and access policy | Bypass of intended restrictions |

## 3. Process and trust boundaries

```text
remote client
    |
    | TCP + SSH
    v
unprivileged worker (one per connection, uid nobody when monitor is root)
    |  never has root, shadow access, host private keys, or authorized_keys access
    |  parses network input with x/crypto
    |
    | bounded framed RPC + SCM_RIGHTS over a Unix socketpair
    v
privileged monitor (root, reduced capability set after startup)
    |  owns listeners, configuration, host private keys and certificates
    |  reads shadow and authorized_keys, verifies passwords and keys
    |  signs host-key handshake data, authorizes sessions
    |
    | fork/exec, credentials set by the monitor
    v
session launcher (root at exec, drops immediately to the target user)
       applies chroot, rlimits, umask, no_new_privs, groups, gid, uid
       then execs the user shell/command or internal SFTP
```

The worker-to-monitor RPC boundary is security-critical. The monitor treats all worker input as untrusted and derives session identity from its own authenticated connection state, not from client-supplied user names. Responses from the monitor are authoritative to the worker.

### Capability model after startup

After listeners, host keys, authenticator state, and the PID file are ready, the monitor drops capabilities on every Go runtime thread:

- bounding set retained: `CAP_DAC_OVERRIDE`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SYS_CHROOT` (the session launcher needs the uid/gid/chroot caps before dropping to the target user);
- monitor permitted/effective: `CAP_DAC_OVERRIDE`, `CAP_KILL`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SETPCAP`.

`CAP_SETPCAP` is retained because the bounding drop itself requires it. The bounding set is reduced immediately afterwards, so `SETPCAP` can only re-add the small retained set. The permitted/effective reduction is applied before the bounding drop.

Workers are spawned with `nobody` credentials and therefore execute with an empty effective capability set. Sessions run with the target uid/gid/groups and no capabilities. Capability dropping is fail-closed: if the monitor runs as root and cannot drop the full set, startup aborts.

`gosshd` is built with `CGO_ENABLED=0`; the drop is applied with `syscall.AllThreadsSyscall` so all Go-managed threads are updated. Builds using cgo return `ENOTSUP` from that path and therefore fail closed when running as root.

## 4. Attacker models

| Attacker | Capabilities assumed | Primary goals |
| --- | --- | --- |
| Remote unauthenticated | Full control of SSH handshake, authentication messages, and channel requests | Authentication bypass, pre-auth memory corruption, resource exhaustion |
| Remote authenticated user | Valid credentials, arbitrary session commands and file operations | Privilege escalation, access to other users' data, persistence |
| Compromised worker | Full control of the worker process and its RPC stream | Impersonate another user, open unauthorized sessions, exhaust monitor resources |
| Compromised session process | Code execution as the target user | Escape chroot, escalate to root, access host keys or shadow |
| Local unprivileged user | Filesystem and process visibility on the host | Read host keys or shadow, signal other users' sessions |

## 5. Implemented controls

| Control | Location |
| --- | --- |
| Host private keys and host certificates stay in the monitor | `internal/crypto`, `internal/privsep/monitor.go` |
| Host-key signing over RPC with a bounded packet format | `internal/privsep/rpc.go` |
| Per-connection worker runs as `nobody` when the monitor is root | `internal/privsep/monitor.go` |
| Monitor capability reduction and fail-closed bounding set | `internal/privsep/caps.go`, `cmd/gosshd/main.go` |
| Session drops uid/gid/groups, applies `no_new_privs`, rlimits, umask, chroot | `internal/session/launcher.go` |
| Chroot validation (absolute, root-owned, no symlinks, no writable components) | `internal/privsep/chroot.go` |
| Shadow, account status, and access-policy checks | `internal/auth/auth.go`, `internal/nss` |
| NSS-aware lookups via `getent` with short caches and file fallback | `internal/nss` |
| Password length cap, dummy-hash verification, failure delay, per-IP limiter | `internal/auth`, `internal/privsep/limiter.go` |
| Explicit modern algorithm allowlists and weak-algorithm rejection | `internal/crypto/policy.go` |
| `RequiredRSASize` enforced for host, user, and certificate RSA keys | `internal/crypto`, `internal/auth` |
| `authorized_keys` options, certificates, revocation, and `cert-authority` entries | `internal/auth` |
| Monitor-owned connection identity for source/access checks | `internal/privsep/monitor.go` |
| `AuthenticationMethods` composition with per-connection progress | `internal/privsep`, `internal/auth` |
| Authorized-command execution: root-owned absolute binary, configured user, bounded output/time, no shell | `internal/auth/command.go` |
| Forged or unknown session RPC rejection and per-connection state isolation | `internal/privsep` |
| Forwarding, agent, and X11 channels rejected and not advertised | `internal/privsep/worker.go` |
| Authentication negative, privsep, certificate, and config E2E suites | `e2e-tests/suites` |

## 6. Residual risks and assumptions

- The worker is exposed to untrusted network input through `golang.org/x/crypto/ssh`; a memory-safety or parser vulnerability there is outside gosshd's direct control.
- Workers and session processes are not yet sandboxed with seccomp or Landlock (`PRIV-06`).
- `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` output is untrusted and parsed strictly, but the configured command binary runs with the configured user's privileges.
- The monitor retains `CAP_DAC_OVERRIDE` and `CAP_KILL` for shadow/authorized-key access and session signaling. A monitor compromise therefore has more reach than a worker compromise.
- The root-at-exec session launcher window is small but exists; hardening it further requires additional process-level sandboxing.
- Forged-RPC coverage currently exercises the socket protocol and rejection paths; a full adversarial worker harness is still pending (`PRIV-08`).
- `Match` blocks are not implemented yet; configurations using them are rejected rather than silently weakened.
- Forwarding is intentionally disabled for v1.
- PAM, FIPS 140-3 mode, and Ed448 are deferred; the first two are explicitly unsupported, and Ed448 is unavailable in the current x/crypto baseline.
- The `setpriv`-based access-denial checks in E2E are best-effort and skipped if the tool is unavailable.

## 7. Non-goals

- Protecting against a compromised root account or a compromised kernel.
- Hiding the server version or resisting targeted denial-of-service beyond the configured connection and authentication limits.
- Supporting password backends other than crypt formats in v1.
- Providing a full OpenSSH feature and configuration parity surface in v1.

## 8. Review checklist

- New RPCs validate session ownership and bounds; they never trust worker-supplied identity.
- New filesystem access in the monitor is justified against the retained capability set.
- New session behavior drops privileges before touching user-controlled paths.
- New config directives are either implemented or rejected; no directive is silently ignored when it affects security.
- New E2E suites run on Debian, Ubuntu, and Fedora.
- `make ci` passes, including race, staticcheck, and govulncheck.
