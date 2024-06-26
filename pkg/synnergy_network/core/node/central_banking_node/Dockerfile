# Use an official Go runtime as a parent image
FROM golang:1.18-alpine as builder

# Set the working directory in the Docker image
WORKDIR /go/src/app

# Copy the Go Modules manifests
COPY go.mod go.sum ./
# Install any needed dependencies
RUN go mod download

# Copy the local package files to the container's workspace.
COPY . .

# Build the application.
RUN CGO_ENABLED=0 GOOS=linux go build -v -o central_banking_node

# Use a minimal alpine image for the production build
FROM alpine:latest  
RUN apk --no-cache add ca-certificates

# Define the working directory in the Docker image
WORKDIR /root/

# Copy the binary from the builder stage to the production image
COPY --from=builder /go/src/app/central_banking_node .

# Expose the port the app runs on
EXPOSE 8000

# Run the binary
CMD ["./central_banking_node"]
