# Use an official Golang runtime as a parent image
FROM golang:1.18-alpine

# Set the working directory in the container
WORKDIR /app

# Copy the local package files to the container's workspace.
ADD . /app

# Install necessary Go packages and dependencies
RUN go mod download
RUN go mod verify

# Install additional system dependencies
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
RUN apk add --update tzdata
RUN apk add --no-cache bash

# Ensuring use of the latest security packages
RUN apk upgrade --available && sync

# Copy the source code into the container
COPY . .

# Build the application
RUN go build -v -o bank_institutional_node

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Define environment variable
ENV NODE_ENV production

# Run the binary program produced by `go install`
CMD ["./bank_institutional_node"]
