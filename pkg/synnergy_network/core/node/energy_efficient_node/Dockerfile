# Use an official Golang runtime as a parent image
FROM golang:1.17-alpine

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Install necessary dependencies
RUN apk update && \
    apk add --no-cache git && \
    go mod tidy

# Build the Go app
RUN go build -o main .

# Run the executable
CMD ["./main"]

# Expose port for the node to communicate
EXPOSE 8080

# Label the image for better organization
LABEL maintainer="Synthron Blockchain <support@synthron.org>"
LABEL version="1.0"
LABEL description="Docker image for Synthron Blockchain Energy-Efficient Node"
