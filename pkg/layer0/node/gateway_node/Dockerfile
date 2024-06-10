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

# Build the gateway node binary
RUN go build -o gateway_node ./pkg/layer0/node/gateway_node

# Final image
FROM alpine:latest

# Install necessary packages
RUN apk --no-cache add ca-certificates && \
    apk add --no-cache tzdata

# Copy the built binary and configuration files
COPY --from=build /app/gateway_node /usr/local/bin/gateway_node
COPY ./config/config.yaml /etc/gateway_node/config.yaml

# Create a non-root user to run the gateway node
RUN addgroup -S gateway && adduser -S gateway -G gateway

# Change ownership of the necessary directories
RUN chown -R gateway:gateway /usr/local/bin/gateway_node /etc/gateway_node

# Switch to the non-root user
USER gateway

# Expose necessary ports
EXPOSE 8080 8443

# Set environment variables for configuration
ENV CONFIG_PATH=/etc/gateway_node/config.yaml

# Run the gateway node
ENTRYPOINT ["gateway_node"]
CMD ["-config", "/etc/gateway_node/config.yaml"]
