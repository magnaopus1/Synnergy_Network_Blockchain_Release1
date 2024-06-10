package config

import (
	"os"
	"strconv"
)

// NetworkConfig holds all necessary network settings for the blockchain token deployment.
type NetworkConfig struct {
	NodeURL             string // URL of the blockchain node
	ChainID             int    // Identifier for the Ethereum network (Mainnet, Ropsten, Rinkeby, etc.)
	GasLimit            uint64 // Gas limit for transactions
	GasPrice            uint64 // Gas price to use in transactions
	TokenDeploymentGas  uint64 // Specific gas limit for token deployment transactions
	PrivateKey          string // Private key for the deploying wallet
	DefaultSendOptions  SendOptions // Default transaction sending options
}

// SendOptions represents the options for sending transactions on the blockchain.
type SendOptions struct {
	From        string // Address of the transaction sender
	Nonce       uint64 // Nonce of the transaction
	Value       uint64 // Value in Wei to send
	GasPrice    uint64 // Gas price to use for this transaction
	GasLimit    uint64 // Gas limit for the transaction
}

// NewNetworkConfig initializes a new NetworkConfig with default or environment-overridden values.
func NewNetworkConfig() *NetworkConfig {
	return &NetworkConfig{
		NodeURL:             getEnv("NODE_URL", "http://localhost:8545"),
		ChainID:             getEnvAsInt("CHAIN_ID", 1),
		GasLimit:            getEnvAsUint64("GAS_LIMIT", 21000),
		GasPrice:            getEnvAsUint64("GAS_PRICE", 5000000000), // 5 Gwei
		TokenDeploymentGas:  getEnvAsUint64("TOKEN_DEPLOYMENT_GAS", 1500000),
		PrivateKey:          getEnv("PRIVATE_KEY", ""),
		DefaultSendOptions:  SendOptions{
			From:       getEnv("DEPLOYER_ADDRESS", ""),
			Nonce:      0, // Typically, this should be fetched dynamically
			Value:      0,
			GasPrice:   getEnvAsUint64("GAS_PRICE", 5000000000),
			GasLimit:   getEnvAsUint64("GAS_LIMIT", 21000),
		},
	}
}

// getEnv fetches a string environment variable or returns a default value.
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvAsInt fetches an integer environment variable or returns a default value.
func getEnvAsInt(key string, defaultValue int) int {
	if valueStr, exists := os.LookupEnv(key); exists {
		if value, err := strconv.Atoi(valueStr); err == nil {
			return value
		}
	}
	return defaultValue
}

// getEnvAsUint64 fetches a uint64 environment variable or returns a default value.
func getEnvAsUint64(key string, defaultValue uint64) uint64 {
	if valueStr, exists := os.LookupEnv(key); exists {
		if value, err := strconv.ParseUint(valueStr, 10, 64); err == nil {
			return value
		}
	}
	return defaultValue
}
