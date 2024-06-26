# Use the official Golang image as the base image
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
RUN CGO_ENABLED=0 GOOS=linux go build -o /staking_node

# Use a minimal base image to reduce the attack surface and image size
FROM alpine:latest

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /staking_node .

# Copy configuration and scripts
COPY config.toml .
COPY scripts/start.sh /usr/local/bin/start.sh
COPY scripts/stop.sh /usr/local/bin/stop.sh
COPY scripts/health_check.sh /usr/local/bin/health_check.sh

# Make the start script executable
RUN chmod +x /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/stop.sh
RUN chmod +x /usr/local/bin/health_check.sh

# Expose the port that the node will run on
EXPOSE 8080

# Command to run the executable
CMD ["/usr/local/bin/start.sh"]
