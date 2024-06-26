# Use the official Golang image as a base image for building the application
FROM golang:1.20-alpine AS builder

# Install necessary build tools and dependencies
RUN apk add --no-cache git

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o geospatial-node .

# Use a minimal Docker image for running the application
FROM alpine:latest

# Install necessary libraries
RUN apk add --no-cache ca-certificates

# Create a non-root user and switch to it
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the pre-built binary from the builder stage
COPY --from=builder /app/geospatial-node /app/geospatial-node

# Copy configuration and necessary files
COPY --from=builder /app/config.toml /app/config.toml

# Expose the port that the application will run on
EXPOSE 8081

# Run the executable
ENTRYPOINT ["./geospatial-node"]

# Health check to ensure the container is running correctly
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s CMD curl -f http://localhost:8081/health || exit 1
