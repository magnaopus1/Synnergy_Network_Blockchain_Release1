# Use an official Golang runtime as a parent image
FROM golang:1.17-alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o optimization_node .

# Use a minimal base image for the final container
FROM alpine:latest

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the Pre-built binary file from the builder stage
COPY --from=builder /app/optimization_node .

# Copy the configuration file
COPY --from=builder /app/config.toml .

# Copy the scripts
COPY --from=builder /app/scripts/start.sh /scripts/start.sh
COPY --from=builder /app/scripts/stop.sh /scripts/stop.sh
COPY --from=builder /app/scripts/health_check.sh /scripts/health_check.sh

# Copy any additional required directories
COPY --from=builder /app/data /data
COPY --from=builder /app/logs /logs

# Make the start script executable
RUN chmod +x /scripts/start.sh

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["/scripts/start.sh"]
