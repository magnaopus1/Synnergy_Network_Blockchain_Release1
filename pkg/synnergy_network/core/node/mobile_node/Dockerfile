# Use a lightweight base image with Go installed
FROM golang:1.18-alpine AS builder

# Install necessary build tools
RUN apk add --no-cache git gcc musl-dev

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o /mobile_node /app/mobile_node.go

# Final stage: a minimal image
FROM alpine:latest

# Install necessary CA certificates
RUN apk --no-cache add ca-certificates

# Create a directory for the app
WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /mobile_node .

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./mobile_node"]
