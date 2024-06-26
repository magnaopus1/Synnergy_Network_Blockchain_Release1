# Use the latest official Golang image as the base image
FROM golang:latest AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o synthron_node ./cmd/synthron_node

# Start a new stage from scratch
FROM alpine:latest  

# Install SSL ca certificates
RUN apk --no-cache add ca-certificates

# Create an app user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/synthron_node .

# Copy the TLS certificates
COPY ./certs /etc/ssl/certs

# Copy the node configuration file
COPY ./configs/node_config.toml .

# Expose the required ports
EXPOSE 30303 8545 8546

# Set environment variables
ENV NODE_TYPE=archival
ENV CONFIG_FILE=/root/node_config.toml

# Chown all the files to the app user
RUN chown -R appuser:appgroup /root

# Change to the app user
USER appuser

# Command to run the executable
CMD ["./synthron_node", "--config", "/root/node_config.toml"]
