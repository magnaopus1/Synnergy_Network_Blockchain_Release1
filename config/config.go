package config

import (
	"os"
	"log"
	"strconv"
)

// Config holds all configuration for the blockchain system.
type Config struct {
	BlockSize         int    // Maximum number of transactions per block
	ConsensusProtocol string // Consensus protocol, e.g., 'PoW', 'PoS'
	NetworkPort       int    // Network port for peer connections
	BlockchainDBPath  string // File path for blockchain data storage
}

// LoadConfig loads configuration from environment variables or defaults.
func LoadConfig() *Config {
	return &Config{
		BlockSize:         getEnvAsInt("BLOCK_SIZE", 500),
		ConsensusProtocol: getEnvAsString("CONSENSUS_PROTOCOL", "PoS"),
		NetworkPort:       getEnvAsInt("NETWORK_PORT", 8080),
		BlockchainDBPath:  getEnvAsString("BLOCKCHAIN_DB_PATH", "./blockchain.db"),
	}
}

// getEnvAsString reads an environment variable and returns a string or a default value.
func getEnvAsString(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvAsInt reads an environment variable and returns it as an integer or a default value.
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnvAsString(key, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

// Setup function to handle any initial setup needed for the configuration.
func Setup() {
	config := LoadConfig()
	log.Printf("Config loaded: %+v\n", config)

	// Any other initial setup steps can be added here
	// This could include initializing databases, setting up network peers, etc.
}

func init() {
	// Setup configuration and any essential services at the initialization stage of the application.
	Setup()
}
