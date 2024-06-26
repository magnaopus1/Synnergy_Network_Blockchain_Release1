# Use an official golang image as the base image
FROM golang:1.19-alpine

# Set environment variables
ENV GO111MODULE=on
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH

# Install necessary dependencies
RUN apk update && \
    apk add --no-cache git bash build-base && \
    rm -rf /var/cache/apk/*

# Create directories for the application
RUN mkdir -p /app/config /app/data /app/logs

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum files to the workspace
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o experimental_node .

# Expose ports (customize if necessary)
EXPOSE 8080

# Copy configuration file
COPY config.toml /app/config/

# Define environment variables for the node
ENV CONFIG_PATH=/app/config/config.toml
ENV DATA_PATH=/app/data
ENV LOG_PATH=/app/logs
ENV NODE_ENV=production

# Define the command to run the application
CMD ["./experimental_node", "--config", "/app/config/config.toml"]
