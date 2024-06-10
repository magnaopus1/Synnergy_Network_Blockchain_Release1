# Dockerfile for Synthron Super Node

# Use an official golang image as a base image
FROM golang:1.16-alpine AS build

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

# Stage 2 - Create a small image
FROM alpine:latest

# Install SSL ca certificates for secure connection, bash for scripts, curl for health checks
RUN apk --no-cache add ca-certificates bash curl

# Set environment variables
ENV CONFIG_PATH=/config/config.toml

# Create appuser
RUN adduser -D -g '' appuser
USER appuser

# Set the Current Working Directory inside the container
WORKDIR /home/appuser

# Copy the Pre-built binary file from the previous stage
COPY --from=build /app/main .

# Copy configuration file and scripts
COPY --from=build /app/config.toml /config/config.toml
COPY --from=build /app/scripts/start.sh /scripts/start.sh
COPY --from=build /app/scripts/stop.sh /scripts/stop.sh
COPY --from=build /app/scripts/health_check.sh /scripts/health_check.sh

# Make scripts executable
RUN chmod +x /scripts/start.sh /scripts/stop.sh /scripts/health_check.sh

# Expose necessary ports
EXPOSE 8080 8081

# Command to run the executable
CMD ["/scripts/start.sh"]
