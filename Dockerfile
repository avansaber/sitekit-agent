# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o sentinel ./cmd/sentinel

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    git \
    systemd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/hostman

# Copy binary
COPY --from=builder /app/sentinel /opt/hostman/sentinel

# Copy config example
COPY configs/agent.yaml.example /opt/hostman/agent.yaml

# Environment variables
ENV HOSTMAN_SAAS_URL=http://localhost
ENV HOSTMAN_AGENT_TOKEN=test-token
ENV HOSTMAN_SERVER_ID=test-server

# Run agent
CMD ["/opt/hostman/sentinel"]
