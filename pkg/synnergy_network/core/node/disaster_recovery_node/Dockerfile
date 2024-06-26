# Use an official Golang image as a parent image
FROM golang:1.17-alpine

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the Go Modules manifests
COPY go.mod go.sum ./

# Install the dependencies
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o main .

# Stage 2
FROM alpine:latest  

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=0 /app/main .

# Copy configuration file and scripts
COPY config.toml /root/
COPY scripts/start.sh /root/
COPY scripts/stop.sh /root/
COPY scripts/health_check.sh /root/

# Add execute permission to scripts
RUN chmod +x /root/start.sh
RUN chmod +x /root/stop.sh
RUN chmod +x /root/health_check.sh

# Expose port
EXPOSE 8080

# Command to run the executable
CMD ["./start.sh"]
