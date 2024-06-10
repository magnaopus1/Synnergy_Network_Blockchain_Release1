# Use an official Golang image as the base image
FROM golang:1.18-alpine as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o historical_node .

# Use a minimal base image
FROM alpine:latest

# Install ca-certificates to be able to make HTTPS requests
RUN apk --no-cache add ca-certificates

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/historical_node .

# Copy configuration files and scripts
COPY config.toml /root/
COPY scripts/ /root/scripts/

# Make sure all scripts are executable
RUN chmod +x /root/scripts/*.sh

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./historical_node"]
