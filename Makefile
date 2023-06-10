NAME  ?= node
CTL   ?= wmctl
REPO  ?= ghcr.io/webmeshproj
IMAGE ?= $(REPO)/$(NAME):latest

ARCH ?= $(shell go env GOARCH)
OS   ?= $(shell go env GOOS)

VERSION_PKG := github.com/webmeshproj/$(NAME)/pkg/version
VERSION     := $(shell git describe --tags --always --dirty)
COMMIT      := $(shell git rev-parse HEAD)
DATE        := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS     ?= -s -w -extldflags=-static -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(COMMIT) -X $(VERSION_PKG).BuildDate=$(DATE)
BUILD_TAGS  ?= osusergo,netgo,sqlite_omit_load_extension,sqlite_vacuum_incr,sqlite_json

build: fmt vet generate ## Build node binary.
	go build \
		-tags $(BUILD_TAGS) \
		-ldflags "$(LDFLAGS)" \
		-o dist/$(NAME)_$(OS)_$(ARCH) \
		cmd/$(NAME)/main.go

build-ctl: fmt vet ## Build wmctl binary.
	go build \
		-tags $(BUILD_TAGS) \
		-ldflags "$(LDFLAGS)" \
		-o dist/$(CTL)_$(OS)_$(ARCH) \
		cmd/$(CTL)/main.go

tidy:
	go mod tidy

lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run

DIST        := $(CURDIR)/dist
BUILD_IMAGE ?= $(REPO)/node-buildx
.PHONY: dist
dist:
	mkdir -p $(DIST)
	docker buildx build -t $(BUILD_IMAGE) -f Dockerfile.build --load .
	docker run --rm \
		-u $(shell id -u):$(shell id -g) \
		-v "$(CURDIR):/build" \
		-v "$(shell go env GOCACHE):/.cache/go-build" \
		-v "$(shell go env GOPATH):/go" \
		-e GOPATH=/go \
		-w /build \
		$(NAME)-build make -j $(shell nproc) dist-node dist-ctl

dist-node: ## Build node binaries for all platforms.
	$(MAKE) \
		dist-node-linux-amd64 \
		dist-node-linux-arm64 \
		dist-node-linux-arm
	upx --best --lzma $(DIST)/$(NAME)_*

dist-ctl: ## Build wmctl binaries for all platforms.
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

define dist-build
	CGO_ENABLED=1 GOOS=$(2) GOARCH=$(3) CC=$(4) \
		go build \
			-tags $(BUILD_TAGS) \
			-ldflags "$(LDFLAGS)" \
			-o $(DIST)/$(1)_$(2)_$(3) \
			cmd/$(1)/main.go
endef

DOCKER ?= docker

docker-build: build ## Build the node docker image
	IMAGE=$(IMAGE) docker-compose build

docker-build-distroless: build ## Build the node docker image
	docker build \
		-f Dockerfile.distroless \
		-t $(IMAGE)-distroless .

docker-push: docker-build ## Push the node docker image
	IMAGE=$(IMAGE) docker-compose push

compose-up: ## Run docker-compose stack.
	IMAGE=$(IMAGE) docker-compose up

pull-db:
	docker-compose cp bootstrap-node-1:/data/webmesh.sqlite ./webmesh.sqlite

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

SQLC_CONFIG := pkg/meshdb/models/sql/sqlc.yaml
generate: ## Generate SQL code.
	go install github.com/kyleconroy/sqlc/cmd/sqlc@latest
	sqlc -f $(SQLC_CONFIG) generate

install-ctl:
	go install github.com/webmeshproj/$(NAME)/cmd/$(CTL)

clean:
	rm -rf dist
	rm -rf webmesh.sqlite
