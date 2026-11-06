# gosshd

A Linux SSH server built on `golang.org/x/crypto/ssh`, targeting a minimal feature surface and modern cryptography.

## Status

This is an early implementation. The current tree includes:

- `sshd_config` parsing for the core authentication, session, crypto, and access-control directives
- explicit modern KEX/cipher/MAC/host-key policy with weak algorithm rejection
- NSS-aware account/shadow lookup through `getent` with a file fallback, plus pure-Go yescrypt/SHA-crypt/bcrypt verification
- `authorized_keys` parsing with key options and `cert-authority` entries
- OpenSSH user/host certificate support
- rate limiting, failure delay, and `RequiredRSASize` enforcement
- privileged monitor, unprivileged per-connection workers, and per-session launchers
- PTY, shell, `exec`, environment, signal, resize, and exit-status handling
- in-process `internal-sftp` and external subsystem support
- Podman-based end-to-end test harness with Debian, Ubuntu, and Fedora images

Still to complete:

- `Match` block parsing and evaluation
- `AuthorizedKeysCommand` / `AuthorizedPrincipalsCommand` execution
- full certificate option parity
- optional PAM backend
- broader OpenSSH configuration compatibility and hardening work

## Documentation

- [Implementation plan](docs/implementation-plan.md)
- [Threat model](docs/threat-model.md)
- [Remaining tasks and verification tracker](docs/remaining-tasks.md)

## Build

```sh
CGO_ENABLED=0 go build -trimpath -o bin/gosshd ./cmd/gosshd
```

## Test

```sh
go test ./...
make ci
```

`make ci` runs the build, unit tests, `go vet`, the race detector, `staticcheck`, and `govulncheck`.

## End-to-end tests

```sh
make e2e-images
make e2e
```

The e2e driver builds `gosshd` and `go test -c` suite binaries, then the `e2e-tests/harness` package runs those binaries inside ephemeral Podman containers. Test data, users, host keys, and configs are created inside the containers.

Useful environment variables:

```text
GOSSHD_E2E_IMAGES=debian,ubuntu,fedora
GOSSHD_E2E_SUITES=smoke,auth,privsep,config,cert,interop
GOSSHD_E2E_KEEP=1
GOSSHD_E2E_REQUIRE=1
```

## Specifications

The requested RFC text files are stored under `specifications/`.
