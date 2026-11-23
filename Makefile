VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test

build:
	go build -ldflags "-X github.com/edwinlmm/aipack/cmd.version=$(VERSION)" -o aipack .

test:
	go test -race ./...
