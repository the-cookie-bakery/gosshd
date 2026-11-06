GO ?= go
CGO_ENABLED ?= 0
E2E_IMAGES ?= debian,ubuntu,fedora
E2E_IMAGE_LIST ?= debian ubuntu fedora
E2E_SUITES ?= smoke,auth,privsep,config,cert,interop,sftp,daemon
STATICCHECK_VERSION ?= latest
GOVULNCHECK_VERSION ?= latest

.PHONY: build test unit e2e e2e-images e2e-clean fmt vet tidy race staticcheck govulncheck fuzz ci

build:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -o bin/gosshd ./cmd/gosshd

test: unit

unit:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

race:
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

fmt:
	gofmt -w cmd internal e2e-tests

vet:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) vet ./...

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

govulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

fuzz:
	$(GO) test -run=^$$ -fuzz=FuzzParseReader -fuzztime=10s ./internal/config
	$(GO) test -run=^$$ -fuzz=FuzzScanAuthorizedKeys -fuzztime=10s ./internal/auth
	$(GO) test -run=^$$ -fuzz=FuzzPacketDecode -fuzztime=10s ./internal/privsep
	$(GO) test -run=^$$ -fuzz=FuzzParseInternalSFTP -fuzztime=10s ./internal/session

ci: build unit vet race staticcheck govulncheck

tidy:
	$(GO) mod tidy

e2e-images:
	for image in $(E2E_IMAGE_LIST); do \
		podman build -t gosshd-e2e-$$image:local -f e2e-tests/images/$$image/Containerfile e2e-tests/images/$$image || exit 1; \
	done

e2e:
	GOSSHD_E2E_IMAGES=$(E2E_IMAGES) GOSSHD_E2E_SUITES=$(E2E_SUITES) $(GO) test -tags=e2e -count=1 -timeout=30m -v ./e2e-tests

e2e-clean:
	-podman rm -f $$(podman ps -aq --filter name=gosshd-e2e-) 2>/dev/null
	-rm -rf e2e-tests/.artifacts
