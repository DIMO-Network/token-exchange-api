.PHONY: all deps docker docker-cgo clean docs test test-race fmt lint install deploy-docs

SHELL := /bin/bash
PATHINSTBIN = $(abspath ./bin)
export PATH := $(PATHINSTBIN):$(PATH)
TAGS =

BIN_NAME					?= token-exchange-api
DEFAULT_INSTALL_DIR			:= $(go env GOPATH)/$(PATHINSTBIN)
DEFAULT_ARCH				:= $(shell go env GOARCH)
DEFAULT_GOOS				:= $(shell go env GOOS)
ARCH						?= $(DEFAULT_ARCH)
GOOS						?= $(DEFAULT_GOOS)
INSTALL_DIR					?= $(DEFAULT_INSTALL_DIR)
.DEFAULT_GOAL 				:= run

LD_FLAGS   =
GO_FLAGS   =
DOCS_FLAGS =
GOLANGCI_VERSION   = latest
PROTOC_VERSION             = 28.3
PROTOC_GEN_GO_VERSION      = $(shell go list -m -f '{{.Version}}' google.golang.org/protobuf)
PROTOC_GEN_GO_GRPC_VERSION = v1.5.1

help:
	@echo "\nSpecify a subcommand:\n"
	@grep -hE '^[0-9a-zA-Z_-]+:.*?## .*$$' ${MAKEFILE_LIST} | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[0;36m%-20s\033[m %s\n", $$1, $$2}'
	@echo ""
	
deps:
	@go mod tidy
	@go mod vendor

SOURCE_FILES = $(shell find lib internal -type f -name "*.go")


$(PATHINSTBIN)/%: $(SOURCE_FILES) 
	@go build $(GO_FLAGS) -tags "$(TAGS)" -ldflags "$(LD_FLAGS) " -o $@ ./cmd/$*

$(APPS): %: $(PATHINSTBIN)/%

docker-tags:
	@echo "latest,$(VER_CUT),$(VER_MAJOR).$(VER_MINOR),$(VER_MAJOR)" > .tags

docker: deps
	@docker build -f ./resources/docker/Dockerfile . -t dimozone/token-exchange-api:$(VER_CUT)
	@docker tag dimozone/token-exchange-api:$(VER_CUT) dimozone/token-exchange-api:latest

build: ## build binary
	@CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(ARCH) \
		go build -o $(PATHINSTBIN)/$(BIN_NAME) ./cmd/$(BIN_NAME)

run: build ## run binary
	@./$(PATHINSTBIN)/$(BIN_NAME

clean: ## clean build artifacts
	@rm -rf $(PATHINSTBIN)
	
install: build ## install binary
	@install -d $(INSTALL_DIR)
	@rm -f $(INSTALL_DIR)/$(BIN_NAME)
	@cp $(PATHINSTBIN)/$(BIN_NAME) $(INSTALL_DIR)/$(BIN_NAME)

lint: ## run linter
	@PATH=$$PATH golangci-lint run --timeout 10m

test: build
	@go test $(GO_FLAGS) -timeout 10m -race -v ./...

tools: tools-golangci-lint tools-protoc tools-protoc-gen-go tools-protoc-gen-go-grpc## install all tools

tools-golangci-lint: ## install golangci-lint
	@mkdir -p $(PATHINSTBIN)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | BINARY=golangci-lint bash -s -- ${GOLANGCI_VERSION}

tools-protoc:
	@mkdir -p $(PATHINSTBIN)
	rm -rf $(PATHINSTBIN)/protoc
ifeq ($(shell uname | tr A-Z a-z), darwin)
	curl -L https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-osx-x86_64.zip > bin/protoc.zip
endif
ifeq ($(shell uname | tr A-Z a-z), linux)
	curl -L https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip > bin/protoc.zip
endif
	unzip -o $(PATHINSTBIN)/protoc.zip -d $(PATHINSTBIN)/protoclib 
	mv -f $(PATHINSTBIN)/protoclib/bin/protoc $(PATHINSTBIN)/protoc
	rm -rf $(PATHINSTBIN)/include
	mv $(PATHINSTBIN)/protoclib/include $(PATHINSTBIN)/ 
	rm $(PATHINSTBIN)/protoc.zip

tools-protoc-gen-go:
	@mkdir -p $(PATHINSTBIN)
	rm -f $(PATHINSTBIN)/protoc-gen-go
	curl -L https://github.com/protocolbuffers/protobuf-go/releases/download/${PROTOC_GEN_GO_VERSION}/protoc-gen-go.${PROTOC_GEN_GO_VERSION}.$(shell uname | tr A-Z a-z).amd64.tar.gz | tar -zOxf - protoc-gen-go > $(PATHINSTBIN)/protoc-gen-go
	@chmod +x $(PATHINSTBIN)/protoc-gen-go

tools-protoc-gen-go-grpc:
	@mkdir -p $(PATHINSTBIN)
	rm -f $(PATHINSTBIN)/protoc-gen-go-grpc
	curl -L https://github.com/grpc/grpc-go/releases/download/cmd/protoc-gen-go-grpc/${PROTOC_GEN_GO_GRPC_VERSION}/protoc-gen-go-grpc.${PROTOC_GEN_GO_GRPC_VERSION}.$(shell uname | tr A-Z a-z).amd64.tar.gz | tar -zOxf - ./protoc-gen-go-grpc > $(PATHINSTBIN)/protoc-gen-go-grpc
	@chmod +x $(PATHINSTBIN)/protoc-gen-go-grpc


generate: generate-swagger go-generate generate-grpc

go-generate:## run go generate
	@go generate ./...

generate-swagger: ## generate swagger documentation
	@go tool swag -version
	go tool swag init -g cmd/token-exchange-api/main.go --parseDependency --parseInternal

generate-grpc: ## generate grpc files
	@PATH=$$PATH protoc --version
	@PATH=$$PATH protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    internal/middleware/dex/dex.proto