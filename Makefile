.PHONY: build clean install test release-snapshot help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build:
	@echo "Building go-promptguard $(VERSION)..."
	@go build -ldflags "$(LDFLAGS)" -o bin/go-promptguard ./cmd/go-promptguard
	@echo "✓ Built to bin/go-promptguard"

install:
	@echo "Installing go-promptguard $(VERSION)..."
	@go install -ldflags "$(LDFLAGS)" ./cmd/go-promptguard
	@echo "✓ Installed to $(shell go env GOPATH)/bin/go-promptguard"

clean:
	@rm -rf bin/ dist/
	@go clean
	@echo "✓ Cleaned"

test:
	@go test -v ./...

release-snapshot:
	@goreleaser release --snapshot --clean
	@echo "✓ Snapshot built to dist/"

release-test:
	@goreleaser release --skip=publish --clean
	@echo "✓ Release tested"
