SHELL := /bin/bash

NAME  ?= node
CTL   ?= wmctl
REPO  ?= ghcr.io/webmeshproj
IMAGE ?= $(REPO)/$(NAME):latest
DISTROLESS_IMAGE ?= $(REPO)/$(NAME)-distroless:latest

GO    ?= go
ARCH  ?= $(shell $(GO) env GOARCH)
OS    ?= $(shell $(GO) env GOOS)
GOBIN ?= $(shell $(GO) env GOPATH)/bin

ifeq ($(OS),Windows_NT)
	OS := windows
endif

default: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build

GORELEASER ?= $(GO) run github.com/goreleaser/goreleaser@latest
BUILD_ARGS ?= --snapshot --clean
PARALLEL   ?= $(shell nproc)

build: fmt vet ## Build node and wmctl binaries for the current architecture.
	$(GORELEASER) build --single-target $(BUILD_ARGS) --id node --id wmctl --parallelism=$(PARALLEL)

build-wasm: fmt vet ## Build node wasm binary for the current architecture.
	$(GORELEASER) build $(BUILD_ARGS) --id node-wasm --parallelism=$(PARALLEL)

dist: fmt vet ## Build distribution binaries and packages for all platforms.
	$(GORELEASER) release --skip-sign $(BUILD_ARGS) --parallelism=$(PARALLEL)

DOCKER ?= docker

docker-build: docker-build-bin ## Build the node docker image for the current architecture.
	$(DOCKER) build \
		-f Dockerfile \
		--build-arg PREFIX=node-docker-linux \
		--build-arg TARGETOS=linux \
		--build-arg TARGETARCH=$(ARCH) \
		-t $(IMAGE) .

docker-build-distroless: docker-build-bin ## Build the distroless node docker image for the current architecture.
	$(DOCKER) build \
		-f Dockerfile.distroless \
		--build-arg PREFIX=node-docker-linux \
		--build-arg TARGETOS=linux \
		--build-arg TARGETARCH=$(ARCH) \
		-t $(DISTROLESS_IMAGE) .

docker-build-bin:
	$(GORELEASER) build $(BUILD_ARGS) --id node-docker-linux --single-target

docker-push: docker-build ## Push the node docker image
	$(DOCKER) push $(IMAGE)

docker-push-distroless: docker-build-distroless ## Push the distroless node docker image
	$(DOCKER) push $(DISTROLESS_IMAGE)

##@ Testing

COVERAGE_FILE := coverage.out
TEST_PARALLEL ?= $(shell nproc)
ifndef ($(TEST_PARALLEL))
	TEST_PARALLEL = 8
endif
TEST_ARGS     := -v -cover -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic -parallel=$(TEST_PARALLEL)

ci: fmt vet test-junit lint ## Run all CI tests.

test: ## Run unit tests.
	$(GO) install github.com/kyoh86/richgo@latest
	$(GOBIN)/richgo test $(TEST_ARGS) ./...
	$(GO) tool cover -func=$(COVERAGE_FILE)

test-junit: ## Run unit tests and output junit xml
	$(GO) install github.com/jstemmer/go-junit-report/v2@latest
	$(GO) test $(TEST_ARGS) ./... 2>&1 \
		| $(GOBIN)/go-junit-report -set-exit-code > junit-report.xml
	$(GO) tool cover -func=$(COVERAGE_FILE)

lint: ## Run linters.
	$(GO) run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run --timeout=5m

.PHONY: fmt
fmt: ## Run go fmt against code.
ifeq ($(OS),windows)
	echo "Skipping go fmt on windows"
else
	$(GO) fmt ./...
endif

.PHONY: vet
vet: ## Run go vet against code.
	$(GO) vet ./...

##@ Misc

generate: ## Run go generate against code.
	$(GO) generate ./...

clean: ## Clean up build and development artifacts.
	rm -rf dist/ $(COVERAGE_FILE)

build-ctl:
	$(GORELEASER) build --single-target $(BUILD_ARGS) --id $(CTL) -o dist/$(CTL)

install-ctl: build-ctl
	install -m 755 dist/$(CTL) $(shell go env GOPATH)/bin/$(CTL)

latest-api: ## Used for development and forces a pull of the API off the main branch.
	GOPRIVATE=github.com/webmeshproj $(GO) get -u github.com/webmeshproj/api@main