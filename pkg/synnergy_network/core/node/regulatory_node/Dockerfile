# Dockerfile for the Synnergy Network Regulatory Node

# Use the official Golang image as the base image
FROM golang:1.17-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the go.mod and go.sum files to the container
COPY go.mod go.sum ./

# Download and cache the Go modules
RUN go mod download

# Copy the source code to the container
COPY . .

# Build the Go application
RUN go build -o regulatory_node .

# Expose the port the app runs on
EXPOSE 8080

# Run the executable
CMD ["./regulatory_node"]
