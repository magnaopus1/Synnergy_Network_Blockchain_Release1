# Use an official Golang runtime as a parent image
FROM golang:1.19-alpine

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the Go Modules manifests
COPY go.mod go.sum ./

# Install Go Modules
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o main .

# This container exposes port 8080 to the outside world
EXPOSE 8080

# Run the executable
CMD ["./main"]
