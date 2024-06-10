# Use an official Go runtime as a parent image
FROM golang:1.18-alpine

# Set the Current Working Directory inside the container
WORKDIR /app

# Install dependencies
RUN apk add --no-cache \
    git \
    bash \
    gcc \
    musl-dev \
    openssl

# Copy the local source code to the container's working directory
COPY . .

# Download dependencies and build the Go application
RUN go mod tidy
RUN go build -o orphan_node ./cmd/orphan_node

# Stage 2: create a minimal image
FROM alpine:latest

# Install dependencies
RUN apk --no-cache add ca-certificates

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the binary from the builder image
COPY --from=0 /app/orphan_node .

# Expose ports
EXPOSE 8080
EXPOSE 8443

# Set environment variables
ENV CONFIG_PATH="/etc/orphan_node/config.toml"
ENV LOG_FILE="/var/log/orphan_node/orphan_node.log"

# Create necessary directories
RUN mkdir -p /etc/orphan_node /var/lib/orphan_node /var/log/orphan_node

# Copy the configuration file
COPY config.toml /etc/orphan_node/config.toml

# Copy scripts
COPY scripts/start.sh /usr/local/bin/start.sh
COPY scripts/stop.sh /usr/local/bin/stop.sh
COPY scripts/health_check.sh /usr/local/bin/health_check.sh

# Ensure the scripts are executable
RUN chmod +x /usr/local/bin/start.sh /usr/local/bin/stop.sh /usr/local/bin/health_check.sh

# Run the start script
CMD ["start.sh"]
