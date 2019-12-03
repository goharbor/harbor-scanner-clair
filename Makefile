SOURCES := $(shell find . -name '*.go')
BINARY := scanner-clair
IMAGE_TAG := dev
IMAGE := goharbor/harbor-scanner-clair:$(IMAGE_TAG)

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOFLAGS=-mod=vendor GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o $(BINARY) cmd/harbor-scanner-clair/main.go

setup:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s v1.21.0

.PHONY: setup

lint:
	./bin/golangci-lint run -v

test: $(SOURCES)
	GOFLAGS=-mod=vendor GO111MODULE=on go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

test-integration: build
	GOFLAGS=-mod=vendor GO111MODULE=on go test -v -tags=integration ./test/integration/...

container: build
	docker build --no-cache -t $(IMAGE) .
