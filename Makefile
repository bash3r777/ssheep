# sshepard — one binary, one file, one key.

SHELL   := /bin/bash
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PKG     := ./cmd/sshepard

.PHONY: help build test vet fmt check cross clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

build: ## Build the sshepard binary into ./bin
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/sshepard $(PKG)

test: ## Run tests
	go test ./...

vet: ## go vet
	go vet ./...

fmt: ## gofmt the tree
	gofmt -w .

check: fmt vet test build ## Format, vet, test and build

cross: ## Cross-compile static binaries into ./dist
	@mkdir -p dist
	@for os in linux darwin windows; do for arch in amd64 arm64; do \
	  ext=""; [ "$$os" = windows ] && ext=".exe"; \
	  echo "  dist/sshepard-$$os-$$arch$$ext"; \
	  GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" \
	    -o dist/sshepard-$$os-$$arch$$ext $(PKG) || exit 1; \
	done; done
	@ls -lh dist/

clean: ## Remove build output
	rm -rf bin dist
