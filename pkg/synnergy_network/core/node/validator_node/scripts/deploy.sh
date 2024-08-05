#!/bin/bash

# Deploy.sh - Script for deploying the Synnergy Network Validator Node

# Ensure the script is executed with root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Variables
NODE_DIR="/var/synnergy/validator_node"
CONFIG_DIR="${NODE_DIR}/configs/validator_node"
LOG_DIR="${NODE_DIR}/logs"
DATA_DIR="${NODE_DIR}/data"
BACKUP_DIR="${NODE_DIR}/backup"
CERT_DIR="${NODE_DIR}/certs"
TLS_CERT_FILE="${CERT_DIR}/tls_cert.pem"
TLS_KEY_FILE="${CERT_DIR}/tls_key.pem"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
BIN_DIR="/usr/local/bin"
NODE_BINARY="synnergy_validator_node"

# Functions

create_directories() {
  echo "Creating necessary directories..."
  mkdir -p ${CONFIG_DIR}
  mkdir -p ${LOG_DIR}
  mkdir -p ${DATA_DIR}
  mkdir -p ${BACKUP_DIR}
  mkdir -p ${CERT_DIR}
}

install_dependencies() {
  echo "Installing necessary dependencies..."
  apt-get update
  apt-get install -y wget curl git build-essential jq
}

generate_tls_certificates() {
  echo "Generating TLS certificates..."
  openssl req -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out ${TLS_CERT_FILE} -keyout ${TLS_KEY_FILE} -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=synnergy-validator-node"
}

download_node_binary() {
  echo "Downloading validator node binary..."
  wget -O ${BIN_DIR}/${NODE_BINARY} "https://example.com/path/to/synnergy_validator_node"
  chmod +x ${BIN_DIR}/${NODE_BINARY}
}

configure_node() {
  echo "Configuring the validator node..."
  cat <<EOL > ${CONFIG_FILE}
[node]
id = "unique-node-id"
name = "Validator Node"
description = "Primary validator node for the Synnergy Network"
data_replication_type = "full"

[network]
host = "0.0.0.0"
port = 30303
max_peers = 50

[consensus]
type = "hybrid"
consensus_algorithm = "synnergy_consensus"
Deactivated_consensus1 = "-"
Deactivated_consensus2 = "-"
staking_active = "yes"
stake_amount = 1000

[security]
use_tls = true
tls_cert_file = "${TLS_CERT_FILE}"
tls_key_file = "${TLS_KEY_FILE}"
enable_mfa = true
firewall_rules = "/etc/iptables/rules.v4"

[storage]
data_dir = "${DATA_DIR}"
log_dir = "${LOG_DIR}"
backup_dir = "${BACKUP_DIR}"

[metrics]
enabled = true
metrics_server = "http://localhost:9090"
log_level = "info"

[governance]
vote_weight = 1.0
proposal_endpoint = "http://localhost:8080/proposals"
voting_endpoint = "http://localhost:8080/vote"

[backup]
schedule = "daily"
backup_retention_days = 30

[operations]
health_check_interval = "5m"
auto_update = true

[incentives]
reward_address = "0xYourWalletAddress"
EOL
}

start_node_service() {
  echo "Creating systemd service for the validator node..."
  cat <<EOL > /etc/systemd/system/synnergy_validator_node.service
[Unit]
Description=Synnergy Validator Node
After=network.target

[Service]
User=root
ExecStart=${BIN_DIR}/${NODE_BINARY} --config ${CONFIG_FILE}
Restart=on-failure
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOL

  systemctl daemon-reload
  systemctl enable synnergy_validator_node.service
  systemctl start synnergy_validator_node.service
}

# Main Script Execution

create_directories
install_dependencies
generate_tls_certificates
download_node_binary
configure_node
start_node_service

echo "Synnergy Validator Node deployed successfully!"
