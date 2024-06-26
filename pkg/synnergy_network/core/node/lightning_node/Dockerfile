# Use an official Golang runtime as a parent image
FROM golang:1.18 as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o lightning_node ./cmd/lightning_node

# Use a minimal Docker image for the final container
FROM debian:buster-slim

# Install CA certificates
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -ms /bin/bash lightning

# Set the Current Working Directory
WORKDIR /home/lightning

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/lightning_node .

# Change ownership of the binary to the non-root user
RUN chown lightning:lightning lightning_node

# Switch to the non-root user
USER lightning

# Expose port 8080 for the Lightning Node to listen on
EXPOSE 8080

# Run the binary program
CMD ["./lightning_node"]
