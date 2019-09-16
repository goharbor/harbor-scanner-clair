SOURCES := $(shell find . -name '*.go')
BINARY := harbor-scanner-clair
IMAGE_TAG := poc
IMAGE := goharbor/harbor-scanner-clair:$(IMAGE_TAG)

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(BINARY) cmd/harbor-scanner-clair/main.go

tests: $(SOURCES)
	GO111MODULE=on go test -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

container: build
	docker build -t $(IMAGE) .
