# Use an official golang runtime as a parent image
FROM golang:1.19-alpine

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Install dependencies
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o main .

# Install BadgerDB
RUN apk add --no-cache git && \
    go get -u github.com/dgraph-io/badger/v3

# Install net-tools for network related commands
RUN apk add --no-cache net-tools

# Set environment variables for secure configurations
ENV PORT=8080
ENV DATABASE_PATH="/data/badger"
ENV MAX_MEMORY_USAGE="128GB"
ENV QUERY_OPTIMIZATION="true"
ENV HIGH_BANDWIDTH_LIMIT="1000MB"

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./main"]

# Health check to ensure the service is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s \
  CMD curl -f http://localhost:8080/health || exit 1
