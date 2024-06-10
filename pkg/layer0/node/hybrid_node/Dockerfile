# Use an official Golang runtime as a parent image
FROM golang:1.18-alpine

# Set environment variables for Go
ENV GO111MODULE=on
ENV GOPROXY=https://proxy.golang.org

# Install dependencies
RUN apk add --no-cache git leveldb bash

# Create and set working directory
WORKDIR /go/src/synthron_blockchain_final/pkg/layer0/node/hybrid_node

# Copy the Go modules manifests
COPY go.mod go.sum ./

# Download the Go module dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go binary
RUN go build -o hybrid_node .

# Expose the port hybrid node listens on
EXPOSE 8080

# Command to run the hybrid node
CMD ["./hybrid_node"]

# Set up a health check script
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD ./scripts/health_check.sh || exit 1
