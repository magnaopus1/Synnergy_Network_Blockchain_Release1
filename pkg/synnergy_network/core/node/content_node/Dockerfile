# Use the official Golang image as the base image
FROM golang:1.18-alpine

# Set environment variables
ENV GO111MODULE=on

# Install necessary packages
RUN apk add --no-cache git

# Create and set the working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN go build -o content_node .

# Expose the port on which the app will run
EXPOSE 8080

# Command to run the executable
CMD ["./content_node"]
