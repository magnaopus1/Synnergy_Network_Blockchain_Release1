#!/bin/bash

# Synthron Blockchain Validator Node Startup Script

# Function to print a message with a timestamp
log_message() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
}

# Function to check if the required software is installed
check_software() {
    log_message "Checking for required software..."

    required_software=("curl" "jq" "docker" "docker-compose")

    for software in "${required_software[@]}"; do
        if ! command -v $software &> /dev/null; then
            log_message "Error: $software is not installed. Please install it and try again."
            exit 1
        fi
    done

    log_message "All required software is installed."
}

# Function to load environment variables from the config file
load_config() {
    log_message "Loading configuration from config.toml..."
    
    if [ ! -f ./config.toml ]; then
        log_message "Error: config.toml file not found."
        exit 1
    fi

    export VALIDATOR_ADDRESS=$(grep 'validator_address' config.toml | awk -F\" '{print $2}')
    export STAKE_AMOUNT=$(grep 'stake_amount' config.toml | awk -F\" '{print $2}')
    export NETWORK_URL=$(grep 'network_url' config.toml | awk -F\" '{print $2}')

    if [ -z "$VALIDATOR_ADDRESS" ] || [ -z "$STAKE_AMOUNT" ] || [ -z "$NETWORK_URL" ]; then
        log_message "Error: Missing required configuration parameters."
        exit 1
    fi

    log_message "Configuration loaded successfully."
}

# Function to start Docker containers
start_docker_containers() {
    log_message "Starting Docker containers..."
    docker-compose up -d
    if [ $? -ne 0 ]; then
        log_message "Error: Failed to start Docker containers."
        exit 1
    fi
    log_message "Docker containers started successfully."
}

# Function to initialize the validator node
initialize_validator_node() {
    log_message "Initializing validator node..."
    
    # Example initialization command (replace with actual command)
    docker exec validator_node_container synthron init --validator-address "$VALIDATOR_ADDRESS" --stake-amount "$STAKE_AMOUNT" --network-url "$NETWORK_URL"

    if [ $? -ne 0 ]; then
        log_message "Error: Failed to initialize validator node."
        exit 1
    fi

    log_message "Validator node initialized successfully."
}

# Function to perform health check
perform_health_check() {
    log_message "Performing health check..."
    ./scripts/health_check.sh
    if [ $? -ne 0 ]; then
        log_message "Error: Health check failed."
        exit 1
    fi
    log_message "Health check completed successfully."
}

# Function to start the validator node
start_validator_node() {
    log_message "Starting validator node..."
    
    # Example start command (replace with actual command)
    docker exec validator_node_container synthron start --config /etc/synthron/config.toml

    if [ $? -ne 0 ]; then
        log_message "Error: Failed to start validator node."
        exit 1
    fi

    log_message "Validator node started successfully."
}

# Main script execution
log_message "Starting Synthron Validator Node..."

check_software
load_config
start_docker_containers
initialize_validator_node
perform_health_check
start_validator_node

log_message "Synthron Validator Node started and running."

# Keep the script running to monitor the logs
log_message "Tailing logs..."
docker logs -f validator_node_container
