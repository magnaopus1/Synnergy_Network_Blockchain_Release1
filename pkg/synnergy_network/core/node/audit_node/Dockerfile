# Use the official Go image as the base image
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
RUN go build -o main .

# Start a new stage from scratch
FROM alpine:latest

# Install dependencies
RUN apk --no-cache add ca-certificates openssl

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/main .

# Copy config files
COPY --from=builder /app/config.toml .

# Copy scripts
COPY --from=builder /app/scripts/health_check.sh /scripts/health_check.sh
COPY --from=builder /app/scripts/start.sh /scripts/start.sh
COPY --from=builder /app/scripts/stop.sh /scripts/stop.sh

# Make scripts executable
RUN chmod +x /scripts/*.sh

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["/scripts/start.sh"]
