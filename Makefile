NAME  ?= node
CTL   ?= wmctl
REPO  ?= ghcr.io/webmeshproj
IMAGE ?= $(REPO)/$(NAME):latest
DISTROLESS_IMAGE ?= $(REPO)/$(NAME)-distroless:latest


GO    ?= go
ARCH  ?= $(shell $(GO) env GOARCH)
OS    ?= $(shell $(GO) env GOOS)

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

build: fmt vet ## Build node and wmctl binary for the local platform.
	$(GORELEASER) build --single-target $(BUILD_ARGS) --id node --id wmctl --id turn --parallelism=$(PARALLEL)

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
	$(GORELEASER) build $(BUILD_ARGS) --id node-docker-linux --parallelism=$(PARALLEL)

docker-push: docker-build ## Push the node docker image
	$(DOCKER) push $(IMAGE)

docker-push-distroless: docker-build-distroless ## Push the distroless node docker image
	$(DOCKER) push $(DISTROLESS_IMAGE)

##@ Testing

COVERAGE_FILE := coverage.out
TEST_ARGS     := -v -cover -coverprofile=$(COVERAGE_FILE) -covermode=atomic -race

test: fmt vet ## Run unit tests.
	$(GO) test $(TEST_ARGS) ./...
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
