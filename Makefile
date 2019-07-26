SOURCES := $(shell find . -name '*.go')
BINARY := scanner-clair
IMAGE_TAG := poc
IMAGE := aquasec/harbor-scanner-clair:$(IMAGE_TAG)

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(BINARY) cmd/scanner-clair/main.go

container: build
	docker build -t $(IMAGE) .

container-run: container
	docker run --name scanner-clair --rm -d -p 8080:8080 \
	-e "SCANNER_ADDR=:8080" \
	-e "SCANNER_CLAIR_URL=http://localhost:6060" \
	$(IMAGE)
