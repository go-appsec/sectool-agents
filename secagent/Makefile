export GO111MODULE = on

.PHONY: build clean test test-cover bench lint

build:
	@mkdir -p bin
	go build -o bin/secagent .

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
