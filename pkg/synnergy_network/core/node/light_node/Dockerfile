# Use an official Golang runtime as a parent image
FROM golang:1.18-alpine

# Set the Current Working Directory inside the container
WORKDIR /app

# Install necessary dependencies
RUN apk add --no-cache git openssl

# Copy the Go Modules manifests
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o ./bin/lightnode ./cmd/lightnode

# Use a minimal image as the final base
FROM alpine:latest

# Add certificates for TLS
RUN apk --no-cache add ca-certificates

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the pre-built binary file from the builder stage
COPY --from=0 /app/bin/lightnode .

# Copy the configuration and other necessary files
COPY --from=0 /app/config.toml .
COPY --from=0 /app/cert.pem .
COPY --from=0 /app/key.pem .
COPY --from=0 /app/ca_cert.pem .

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./lightnode"]
