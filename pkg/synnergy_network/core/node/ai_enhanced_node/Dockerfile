# Use an official Golang runtime as a parent image
FROM golang:1.18 as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o ai_enhanced_node .

# Start a new stage from scratch
FROM debian:buster

# Install ca-certificates
RUN apt-get update && apt-get install -y ca-certificates

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/ai_enhanced_node /usr/local/bin/ai_enhanced_node

# Create app user and group
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/scripts
RUN chown -R appuser:appuser /app

# Copy configuration files and scripts
COPY config.toml /app/config.toml
COPY scripts/health_check.sh /app/scripts/health_check.sh
COPY scripts/start.sh /app/scripts/start.sh
COPY scripts/stop.sh /app/scripts/stop.sh

# Set ownership and permissions
RUN chown -R appuser:appuser /app
RUN chmod +x /app/scripts/*.sh

# Change to non-root privilege
USER appuser

# Expose port if necessary (e.g., 8080)
EXPOSE 8080

# Command to run the executable
CMD ["/app/scripts/start.sh"]
