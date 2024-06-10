# Base image
FROM golang:1.18-alpine AS build

# Set necessary environment variables
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Create working directory
WORKDIR /app

# Copy the Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the API node binary
RUN go build -o api_node ./pkg/layer0/node/api_node

# Final image
FROM alpine:latest

# Install necessary packages
RUN apk --no-cache add ca-certificates && \
    apk add --no-cache tzdata

# Copy the built binary and configuration files
COPY --from=build /app/api_node /usr/local/bin/api_node
COPY ./config/config.toml /etc/api_node/config.toml

# Create a non-root user to run the API node
RUN addgroup -S api && adduser -S api -G api

# Change ownership of the necessary directories
RUN chown -R api:api /usr/local/bin/api_node /etc/api_node

# Switch to the non-root user
USER api

# Expose necessary ports
EXPOSE 8080 8443

# Set environment variables for configuration
ENV CONFIG_PATH=/etc/api_node/config.toml

# Run the API node
ENTRYPOINT ["api_node"]
CMD ["-config", "/etc/api_node/config.toml"]
