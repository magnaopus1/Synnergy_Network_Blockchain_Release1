# Use an official Golang runtime as a parent image
FROM golang:1.18-alpine

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Install dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN go build -o custodial_node .

# Install necessary packages for script execution
RUN apk --no-cache add bash

# Expose the application port
EXPOSE 8080

# Set the environment variables
ENV NODE_PORT=8080
ENV ENCRYPTION_KEY=your_encryption_key
ENV DATABASE_PATH=/app/data
ENV HOT_STORAGE_PATH=/app/data/hot
ENV COLD_STORAGE_PATH=/app/data/cold

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/data/hot /app/data/cold

# Copy scripts
COPY scripts/health_check.sh /usr/local/bin/health_check.sh
COPY scripts/start.sh /usr/local/bin/start.sh
COPY scripts/stop.sh /usr/local/bin/stop.sh

# Ensure scripts are executable
RUN chmod +x /usr/local/bin/health_check.sh
RUN chmod +x /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/stop.sh

# Start the application
CMD ["sh", "/usr/local/bin/start.sh"]
