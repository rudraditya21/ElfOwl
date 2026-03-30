.PHONY: help build ebpf test clean fmt lint run docker

VERSION ?= 0.1.0
BUILD_TIME := $(shell date -u '+%Y-%m-%d %H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo 'unknown')

help:
	@echo "elf-owl build targets:"
	@echo "  make build       - Build elf-owl binary"
	@echo "  make ebpf        - Build eBPF object files (pkg/ebpf/programs/bin/*.o)"
	@echo "  make test        - Run all tests"
	@echo "  make unit-test   - Run unit tests only"
	@echo "  make integration-test - Run integration tests"
	@echo "  make clean       - Remove build artifacts"
	@echo "  make fmt         - Format code"
	@echo "  make lint        - Run linter"
	@echo "  make run         - Run agent locally"
	@echo "  make docker      - Build Docker image"

build:
	@echo "Building elf-owl v$(VERSION)..."
	go build \
		-ldflags="-X main.version=$(VERSION) -X 'main.buildTime=$(BUILD_TIME)' -X main.gitCommit=$(GIT_COMMIT)" \
		-o elf-owl \
		cmd/elf-owl/main.go
	@echo "✓ Binary created: ./elf-owl"

ebpf:
	@echo "Building eBPF objects..."
	$(MAKE) -C pkg/ebpf/programs all
	@echo "✓ eBPF objects ready in pkg/ebpf/programs/bin"

test: unit-test integration-test
	@echo "✓ All tests passed"

unit-test:
	@echo "Running unit tests..."
	go test -v -race -coverprofile=coverage.out ./pkg/...
	@echo "✓ Unit tests passed"

integration-test:
	@echo "Running integration tests..."
	go test -v -race ./test/integration/...
	@echo "✓ Integration tests passed"

clean:
	@echo "Cleaning build artifacts..."
	rm -f elf-owl coverage.out
	go clean
	@echo "✓ Clean complete"

fmt:
	@echo "Formatting code..."
	gofmt -w .
	@echo "✓ Formatting complete"

lint:
	@echo "Running linter..."
	golangci-lint run ./...
	@echo "✓ Linter passed"

run: build
	@echo "Running elf-owl..."
	./elf-owl

docker:
	@echo "Building Docker image..."
	docker build -t elf-owl:$(VERSION) -f Dockerfile .
	@echo "✓ Docker image created: elf-owl:$(VERSION)"

mod-tidy:
	@echo "Tidying Go modules..."
	go mod tidy
	go mod download
	@echo "✓ Modules tidied"

version:
	@echo "elf-owl version $(VERSION)"
	@echo "Build time: $(BUILD_TIME)"
	@echo "Git commit: $(GIT_COMMIT)"
