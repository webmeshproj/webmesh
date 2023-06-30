NAME  ?= node
CTL   ?= wmctl
REPO  ?= ghcr.io/webmeshproj
IMAGE ?= $(REPO)/$(NAME):latest

BUILD_IMAGE ?= $(REPO)/node-buildx:latest

VERSION_PKG := github.com/webmeshproj/$(NAME)/pkg/version
VERSION     := $(shell git describe --tags --always --dirty)
COMMIT      := $(shell git rev-parse HEAD)
DATE        := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
BUILD_TAGS  ?= osusergo,netgo,sqlite_omit_load_extension,sqlite_vacuum_incr,sqlite_foreign_keys

ARCH  ?= $(shell go env GOARCH)
OS    ?= $(shell go env GOOS)

ifeq ($(OS),darwin)
	# We can't do static builds on darwin
	EXTLDFLAGS :=
else
	EXTLDFLAGS := -static
endif

LDFLAGS ?= -s -w -extldflags=$(EXTLDFLAGS) \
			-X $(VERSION_PKG).Version=$(VERSION) \
			-X $(VERSION_PKG).Commit=$(COMMIT) \
			-X $(VERSION_PKG).BuildDate=$(DATE)

DIST  := $(CURDIR)/dist

default: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build

build: fmt vet generate ## Build node binary for the local platform.
	go build \
		-tags "$(BUILD_TAGS)" \
		-ldflags "$(LDFLAGS)" \
		-o "$(DIST)/$(NAME)_$(OS)_$(ARCH)" \
		cmd/$(NAME)/main.go

build-ctl: fmt vet ## Build wmctl binary for the local platform.
	go build \
		-tags "$(BUILD_TAGS)" \
		-ldflags "$(LDFLAGS)" \
		-o "$(DIST)/$(CTL)_$(OS)_$(ARCH)" \
		cmd/$(CTL)/main.go

COVERAGE_FILE ?= coverage.out
TEST_ARGS     ?= -v -race -cover -tags "$(BUILD_TAGS)" -coverprofile=$(COVERAGE_FILE) -covermode=atomic
test: fmt vet
	go test $(TEST_ARGS) ./...
	go tool cover -func=$(COVERAGE_FILE)

lint: ## Run linters.
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run

DOCKER ?= docker

build-image: ## Build the node build image.
	$(DOCKER) build -t $(BUILD_IMAGE) -f Dockerfile.build .

dist-linux: generate ## Build binaries for all Linux platforms.
	rm -rf $(DIST)
	mkdir -p $(DIST)
	docker run --rm \
		-u $(shell id -u):$(shell id -g) \
		-v "$(CURDIR):/build" \
		-v "$(shell go env GOCACHE):/.cache/go-build" \
		-v "$(shell go env GOPATH):/go" \
		-e GOPATH=/go \
		-w /build \
		$(BUILD_IMAGE) make -j $(shell nproc) dist-node dist-ctl
	cd "$(DIST)" ; sha256sum * > sha256sums-linux.txt

dist-darwin: generate ## Build binaries for all Darwin platforms.
	rm -rf $(DIST)
	$(MAKE) dist-node-darwin dist-ctl-darwin
	upx --best --lzma $(DIST)/*
	cd "$(DIST)" ; shasum -a 256 * > sha256sums-darwin.txt

dist-node:
	$(MAKE) \
		dist-node-linux-amd64 \
		dist-node-linux-arm64 \
		dist-node-linux-arm
	upx --best --lzma $(DIST)/$(NAME)_*

dist-ctl:
	$(MAKE) \
		dist-ctl-linux-amd64 \
		dist-ctl-linux-arm64 \
		dist-ctl-linux-arm
	upx --best --lzma $(DIST)/$(CTL)_*

dist-node-linux-amd64:
	$(call dist-build,$(NAME),linux,amd64,x86_64-linux-musl-gcc)

dist-node-linux-arm64:
	$(call dist-build,$(NAME),linux,arm64,aarch64-linux-musl-gcc)

dist-node-linux-arm:
	$(call dist-build,$(NAME),linux,arm,arm-linux-musleabihf-gcc)

dist-ctl-linux-amd64:
	$(call dist-build,$(CTL),linux,amd64,x86_64-linux-musl-gcc)

dist-ctl-linux-arm64:
	$(call dist-build,$(CTL),linux,arm64,aarch64-linux-musl-gcc)

dist-ctl-linux-arm:
	$(call dist-build,$(CTL),linux,arm,arm-linux-musleabihf-gcc)

dist-node-darwin:
	$(call dist-build,$(NAME),darwin,amd64,)
	$(call dist-build,$(NAME),darwin,arm64,)

dist-ctl-darwin:
	$(call dist-build,$(CTL),darwin,amd64,)
	$(call dist-build,$(CTL),darwin,arm64,)

define dist-build
	CGO_ENABLED=1 GOOS=$(2) GOARCH=$(3) CC=$(4) \
		go build \
			-tags "$(BUILD_TAGS)" \
			-ldflags "$(LDFLAGS)" \
			-trimpath \
			-o "$(DIST)/$(1)_$(2)_$(3)" \
			cmd/$(1)/main.go
endef

docker-build: build ## Build the node docker image
	$(DOCKER) build \
		-f Dockerfile \
		-t $(IMAGE) .

docker-build-distroless: build ## Build the distroless node docker image
	$(DOCKER) build \
		-f Dockerfile.distroless \
		-t $(IMAGE)-distroless .

docker-push: docker-build ## Push the node docker image
	$(DOCKER) push $(IMAGE)

docker-push-distroless: docker-build-distroless ## Push the distroless node docker image
	$(DOCKER) push $(IMAGE)-distroless

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

generate: ## Run go generate against code.
	go generate ./...

install-ctl: build-ctl ## Install wmctl binary into $GOPATH/bin.
	install -m 755 $(DIST)/$(CTL)_$(OS)_$(ARCH) $(shell go env GOPATH)/bin/$(CTL)

clean: ## Clean up build and development artifacts.
	rm -rf dist
