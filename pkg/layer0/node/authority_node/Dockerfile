# Dockerfile for Synthron Authority Node

# Use an official Golang runtime as a parent image
FROM golang:1.18-alpine AS builder

# Set environment variables
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Create and set working directory
WORKDIR /go/src/app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN go build -o /go/bin/authority_node

# Use a minimal base image
FROM alpine:latest

# Install necessary packages
RUN apk --no-cache add ca-certificates

# Set working directory
WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /go/bin/authority_node .

# Copy configuration files and scripts
COPY config.toml .
COPY scripts/start.sh /usr/local/bin/start.sh
COPY scripts/stop.sh /usr/local/bin/stop.sh
COPY scripts/health_check.sh /usr/local/bin/health_check.sh

# Ensure the scripts are executable
RUN chmod +x /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/stop.sh
RUN chmod +x /usr/local/bin/health_check.sh

# Expose ports needed for the Authority Node
EXPOSE 8080 30303

# Define default command to run when starting the container
CMD ["/usr/local/bin/start.sh"]
