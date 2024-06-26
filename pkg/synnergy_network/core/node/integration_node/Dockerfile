# Use the official golang image as the base image
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
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /integration_node

# Start a new stage from scratch
FROM alpine:latest

# Install ca-certificates
RUN apk --no-cache add ca-certificates

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /integration_node .

# Copy config and scripts
COPY config.toml /root/config.toml
COPY scripts/start.sh /root/start.sh
COPY scripts/stop.sh /root/stop.sh
COPY scripts/health_check.sh /root/health_check.sh

# Make the start script executable
RUN chmod +x /root/start.sh /root/stop.sh /root/health_check.sh

# Expose port 8080
EXPOSE 8080

# Command to run the executable
CMD ["./start.sh"]
