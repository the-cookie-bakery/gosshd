GO ?= go
CGO_ENABLED ?= 0
E2E_IMAGES ?= debian,ubuntu,fedora
E2E_IMAGE_LIST ?= debian ubuntu fedora
E2E_SUITES ?= smoke

.PHONY: build test unit e2e e2e-images e2e-clean fmt vet tidy

build:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -o bin/gosshd ./cmd/gosshd

test: unit

unit:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

fmt:
	gofmt -w cmd internal e2e-tests

vet:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) vet ./...

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
