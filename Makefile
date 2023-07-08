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

ifeq ($(OS),Windows_NT)
	OS := windows
endif

ifeq ($(OS),freebsd) 
	EXTBUILDFLAGS :=
else
	EXTBUILDFLAGS := -race
endif

ifeq ($(OS),darwin)
	EXTLDFLAGS :=
else
	EXTLDFLAGS := -static
endif

LDFLAGS ?= -s -w \
			-linkmode=external \
			-extldflags=$(EXTLDFLAGS) \
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

ifeq ($(OS),windows)
# Generate is buggy on windows depending on the setup, so comment out for local dev.
# The windows binary is built via Linux in CI.
build: fmt vet ## Build node binary for the local platform.
else
build: fmt vet generate ## Build node binary for the local platform.
endif
	go build $(EXTBUILDFLAGS) \
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

build-image: ## Build the cross-compiler container image.
	$(DOCKER) build -t $(BUILD_IMAGE) -f Dockerfile.build .

dist-linux: generate ## Build distribution binaries for all Linux platforms.
	$(MAKE) build-in-docker DOCKER_BUILD_TARGETS="dist-linux-all"
	upx --best --lzma $(DIST)/*_linux_*

dist-windows: generate ## Build distribution binaries for Windows.
	$(MAKE) build-in-docker DOCKER_BUILD_TARGETS="dist-windows-all"
	upx --best --lzma $(DIST)/*_windows_*

dist-linux-windows: generate ## An alias for dist-linux and dist-windows in a single docker execution.
	$(MAKE) build-in-docker DOCKER_BUILD_TARGETS="dist-linux-windows-all"
	upx --best --lzma $(DIST)/*_linux_* $(DIST)/*_windows_*

dist-darwin: generate ## Build distribution binaries for Darwin.
	$(MAKE) dist-darwin-all
	upx --best --lzma $(DIST)/*_darwin_*

DOCKER_BUILD_TARGETS ?=
build-in-docker:
	mkdir -p $(DIST)
	docker run --rm \
		-u $(shell id -u):$(shell id -g) \
		-v "$(CURDIR):/build" \
		-v "$(shell go env GOCACHE):/.cache/go-build" \
		-v "$(shell go env GOPATH):/go" \
		-e GOPATH=/go \
		-w /build \
		$(BUILD_IMAGE) make -j $(shell nproc) $(DOCKER_BUILD_TARGETS)

dist-linux-all: dist-node-linux-all dist-ctl-linux-all

dist-darwin-all: dist-node-darwin-all dist-ctl-darwin-all

dist-windows-all: dist-node-windows-all dist-ctl-windows-all

dist-linux-windows-all: dist-linux-all dist-windows-all

dist-node-linux-all: dist-node-linux-amd64 dist-node-linux-arm64 dist-node-linux-arm

dist-ctl-linux-all: dist-ctl-linux-amd64 dist-ctl-linux-arm64 dist-ctl-linux-arm

dist-node-darwin-all: dist-node-darwin-amd64 dist-node-darwin-arm64

dist-ctl-darwin-all: dist-ctl-darwin-amd64 dist-ctl-darwin-arm64

dist-node-windows-all: dist-node-windows-amd64

dist-ctl-windows-all: dist-ctl-windows-amd64

dist-node-linux-%:
	$(call dist-build,$(NAME),linux,amd64,x86_64-linux-musl-gcc)

dist-node-linux-arm64:
	$(call dist-build,$(NAME),linux,arm64,aarch64-linux-musl-gcc)

dist-node-linux-arm:
	$(call dist-build,$(NAME),linux,arm,arm-linux-musleabihf-gcc)

dist-node-windows-amd64:
	$(call dist-build,$(NAME),windows,amd64,x86_64-w64-mingw32-gcc)
	mv $(DIST)/$(NAME)_windows_amd64 $(DIST)/$(NAME)_windows_amd64.exe

dist-ctl-linux-amd64:
	$(call dist-build,$(CTL),linux,amd64,x86_64-linux-musl-gcc)

dist-ctl-linux-arm64:
	$(call dist-build,$(CTL),linux,arm64,aarch64-linux-musl-gcc)

dist-ctl-linux-arm:
	$(call dist-build,$(CTL),linux,arm,arm-linux-musleabihf-gcc)

dist-ctl-windows-amd64:
	$(call dist-build,$(CTL),windows,amd64,x86_64-w64-mingw32-gcc)
	mv $(DIST)/$(CTL)_windows_amd64 $(DIST)/$(CTL)_windows_amd64.exe

dist-node-freebsd-amd64:
	$(call dist-build,$(NAME),freebsd,amd64,)

dist-node-freebsd-arm64:
	$(call dist-build,$(NAME),freebsd,arm64,)

dist-node-freebsd-arm:
	$(call dist-build,$(NAME),freebsd,arm,)

dist-ctl-freebsd-amd64:
	$(call dist-build,$(CTL),freebsd,amd64,)

dist-ctl-freebsd-arm64:
	$(call dist-build,$(CTL),freebsd,arm64,)

dist-ctl-freebsd-arm:
	$(call dist-build,$(CTL),freebsd,arm,)

dist-node-darwin-amd64:
	$(call dist-build,$(NAME),darwin,amd64,)

dist-node-darwin-arm64:
	$(call dist-build,$(NAME),darwin,arm64,)

dist-ctl-darwin-amd64:
	$(call dist-build,$(CTL),darwin,amd64,)

dist-ctl-darwin-arm64:
	$(call dist-build,$(CTL),darwin,arm64,)

define dist-build
	CGO_ENABLED=1 GOOS=$(2) GOARCH=$(3) CC=$(4) \
		go build $(EXTBUILDFLAGS) \
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
ifeq ($(OS),windows)
	echo "Skipping go fmt on windows"
else
	go fmt ./...
endif

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

generate: ## Run go generate against code.
	go generate ./...

install-ctl: build-ctl ## Install wmctl binary into $GOPATH/bin.
	install -m 755 $(DIST)/$(CTL)_$(OS)_$(ARCH) $(shell go env GOPATH)/bin/$(CTL)

clean: ## Clean up build and development artifacts.
	rm -rf dist
