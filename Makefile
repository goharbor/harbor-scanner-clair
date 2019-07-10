SOURCES := $(shell find . -name '*.go')
BINARY := clair-adapter
IMAGE := aquasec/harbor-clair-adapter:poc

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(BINARY) cmd/clair-adapter.go

container: build
	docker build -t $(IMAGE) .

container-run: container
	docker run --name clair-adapter --rm -d -p 8080:8080 $(IMAGE)
