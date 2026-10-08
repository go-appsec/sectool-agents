export GO111MODULE = on

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X github.com/go-appsec/sectool-agents/secagent/version.Version=$(VERSION)"

.PHONY: build clean test test-cover bench lint

build:
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/secagent .

clean:
	rm -rf bin/

test:
	go test -race -cover ./...

test-cover:
	go test -race -coverprofile=test.out ./... && go tool cover --html=test.out

bench:
	go test --benchmem -benchtime=20s -bench='Benchmark.*' -run='^$$' ./...

lint:
	golangci-lint run --timeout=600s --config=$(CURDIR)/.golangci.yml && go vet ./...
