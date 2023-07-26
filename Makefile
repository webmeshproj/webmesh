NAME  ?= node
CTL   ?= wmctl
REPO  ?= ghcr.io/webmeshproj
IMAGE ?= $(REPO)/$(NAME):latest
DISTROLESS_IMAGE ?= $(REPO)/$(NAME)-distroless:latest

ARCH  ?= $(shell go env GOARCH)
OS    ?= $(shell go env GOOS)

ifeq ($(OS),Windows_NT)
	OS := windows
endif

default: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build

GORELEASER ?= go run github.com/goreleaser/goreleaser@latest

BUILD_ARGS ?= --snapshot --skip-sign --clean
build: fmt vet ## Build node and wmctl binary for the local platform.
	$(GORELEASER) build --single-target $(BUILD_ARGS) --id node --id wmctl

dist: fmt vet ## Build distribution binaries and packages for all platforms.
	$(GORELEASER) release $(BUILD_ARGS)

DOCKER ?= docker

docker-build: docker-build-bin ## Build the node docker image
	$(DOCKER) build \
		-f Dockerfile \
		--build-arg PREFIX=node-docker-linux \
		--build-arg TARGETOS=linux \
		--build-arg TARGETARCH=$(ARCH) \
		-t $(IMAGE) .

docker-build-distroless: docker-build-bin ## Build the distroless node docker image
	$(DOCKER) build \
		-f Dockerfile.distroless \
		--build-arg PREFIX=node-docker-linux \
		--build-arg TARGETOS=linux \
		--build-arg TARGETARCH=$(ARCH) \
		-t $(DISTROLESS_IMAGE) .

docker-build-bin:
	$(GORELEASER) build $(BUILD_ARGS) --id node-docker-linux

docker-push: docker-build ## Push the node docker image
	$(DOCKER) push $(IMAGE)

docker-push-distroless: docker-build-distroless ## Push the distroless node docker image
	$(DOCKER) push $(DISTROLESS_IMAGE)

##@ Testing

COVERAGE_FILE ?= coverage.out
TEST_ARGS     ?= -v -cover -coverprofile=$(COVERAGE_FILE) -covermode=atomic
test: fmt vet
	go test $(TEST_ARGS) ./...
	go tool cover -func=$(COVERAGE_FILE)

lint: ## Run linters.
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run

.PHONY: fmt
fmt: ## Run go fmt against code.
ifeq ($(OS),windows)
	echo "Skipping go fmt on windows"
else
	go fmt ./...
endif

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

##@ Misc

generate: ## Run go generate against code.
	go generate ./...

clean: ## Clean up build and development artifacts.
	rm -rf dist
