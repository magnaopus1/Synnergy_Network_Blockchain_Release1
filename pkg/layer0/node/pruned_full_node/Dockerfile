# Use an official Golang runtime as a parent image
FROM golang:1.18-alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -o pruned_full_node .

# Use a minimal base image as a parent image
FROM alpine:latest

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the Pre-built binary file from the builder stage
COPY --from=builder /app/pruned_full_node .

# Copy the configuration files
COPY config /root/config

# Copy health check script
COPY scripts/health_check.sh /root/scripts/health_check.sh

# Copy start and stop scripts
COPY scripts/start.sh /root/scripts/start.sh
COPY scripts/stop.sh /root/scripts/stop.sh

# Install required packages
RUN apk --no-cache add curl bash

# Expose the required ports
EXPOSE 8080
EXPOSE 8545

# Run the binary program
CMD ["./pruned_full_node"]
