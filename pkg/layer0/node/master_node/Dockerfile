# Use an official lightweight base image
FROM ubuntu:20.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    curl \
    wget \
    git \
    software-properties-common \
    libssl-dev \
    libffi-dev \
    python3-dev \
    python3-pip \
    python3-venv \
    jq \
    sudo \
    unzip \
    openssl \
    net-tools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Add a user for running the node
RUN useradd -ms /bin/bash nodeuser
USER nodeuser
WORKDIR /home/nodeuser

# Install Go
RUN wget https://dl.google.com/go/go1.18.3.linux-amd64.tar.gz && \
    sudo tar -C /usr/local -xzf go1.18.3.linux-amd64.tar.gz && \
    rm go1.18.3.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Install node software dependencies
COPY --chown=nodeuser:nodeuser go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY --chown=nodeuser:nodeuser . .

# Build the node software
RUN go build -o master_node ./cmd/master_node

# Set up runtime environment
RUN mkdir -p /home/nodeuser/data /home/nodeuser/logs

# Expose necessary ports
EXPOSE 30303 30304

# Start the node
ENTRYPOINT ["./scripts/start.sh"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 CMD ["./scripts/health_check.sh"]

# Clean up
USER root
RUN apt-get purge -y --auto-remove && \
    rm -rf /var/lib/apt/lists/*
