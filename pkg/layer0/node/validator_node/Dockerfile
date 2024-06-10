# Use an official Golang runtime as a parent image
FROM golang:1.17 as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o validator_node ./cmd/validator_node

# Use a minimal Docker image for the final build
FROM debian:bullseye-slim

# Set environment variables
ENV GO_ENV=production

# Install necessary packages
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/validator_node .

# Expose port
EXPOSE 8080 9090

# Command to run the executable
CMD ["./validator_node", "--config", "/root/config/config.json"]
