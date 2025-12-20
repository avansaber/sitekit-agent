.PHONY: build build-linux clean test run

# Build for current platform
build:
	go build -o bin/sentinel ./cmd/sentinel

# Build for Linux (for deployment)
build-linux:
	GOOS=linux GOARCH=amd64 go build -o bin/sentinel-linux-amd64 ./cmd/sentinel

# Build for all platforms
build-all: build build-linux
	GOOS=darwin GOARCH=amd64 go build -o bin/sentinel-darwin-amd64 ./cmd/sentinel
	GOOS=darwin GOARCH=arm64 go build -o bin/sentinel-darwin-arm64 ./cmd/sentinel

# Clean build artifacts
clean:
	rm -rf bin/

# Run tests
test:
	go test -v ./...

# Run agent locally
run:
	go run ./cmd/sentinel

# Install dependencies
deps:
	go mod tidy
	go mod download

# Format code
fmt:
	go fmt ./...

# Lint code
lint:
	golangci-lint run

# Docker build for testing
docker-build:
	docker build -t hostman-agent:latest .

# Docker run for testing
docker-run:
	docker run --rm -it \
		-e HOSTMAN_SAAS_URL=http://host.docker.internal \
		-e HOSTMAN_AGENT_TOKEN=test-token \
		hostman-agent:latest
