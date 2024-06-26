# Use an official Golang runtime as a parent image
FROM golang:1.19-alpine as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN go build -o consensus_node ./main.go

# Use a minimal Docker image for the final build
FROM alpine:latest

# Set up a non-root user for running the node
RUN addgroup -S synthron && adduser -S synthron -G synthron
USER synthron

# Set environment variables
ENV APP_HOME /home/synthron/app
WORKDIR $APP_HOME

# Copy the pre-built binary file from the previous stage
COPY --from=builder /app/consensus_node .

# Copy configuration files
COPY --chown=synthron:synthron ./config.json ./config.json

# Expose the port the app runs on
EXPOSE 8080

# Command to run the executable
CMD ["./consensus_node"]
