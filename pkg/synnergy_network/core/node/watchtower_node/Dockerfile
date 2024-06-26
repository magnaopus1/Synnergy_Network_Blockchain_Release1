# Use the official Golang image as the base image
FROM golang:1.18-alpine

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go app
RUN go build -o watchtower_node .

# Install any necessary tools and dependencies
RUN apk add --no-cache \
    ca-certificates \
    curl \
    bash \
    openssl \
    && update-ca-certificates

# Create a user and group to run the watchtower node securely
RUN addgroup -S watchtower && adduser -S watchtower -G watchtower

# Ensure the application runs with non-root privileges
USER watchtower

# Expose the port the app runs on
EXPOSE 8080

# Command to run the executable
CMD ["./watchtower_node"]
