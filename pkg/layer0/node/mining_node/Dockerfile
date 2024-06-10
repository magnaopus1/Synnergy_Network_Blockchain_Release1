# Use an official Ubuntu as a parent image
FROM ubuntu:20.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

# Update the package list and install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    wget \
    git \
    ca-certificates \
    libssl-dev \
    libgmp-dev \
    software-properties-common \
    cmake \
    pkg-config \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Golang
RUN wget https://golang.org/dl/go1.18.3.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.18.3.linux-amd64.tar.gz && \
    rm go1.18.3.linux-amd64.tar.gz

# Set Golang environment variables
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Set working directory
WORKDIR /usr/src/app

# Copy the application source code
COPY . .

# Install Go dependencies
RUN go mod download

# Build the Go application
RUN go build -o mining_node .

# Expose the port the app runs on
EXPOSE 30303

# Run the application
CMD ["./mining_node"]
