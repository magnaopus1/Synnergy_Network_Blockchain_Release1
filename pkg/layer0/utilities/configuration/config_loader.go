package configuration

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/synthron_blockchain/pkg/layer0/utilities/encryption_utils"
	"github.com/synthron_blockchain/pkg/layer0/utilities/logging_utils"
)

// Config represents the configuration structure for the blockchain system
type Config struct {
	NetworkName           string `json:"network_name"`
	ConsensusAlgorithm    string `json:"consensus_algorithm"`
	MiningDifficulty      int    `json:"mining_difficulty"`
	TransactionFee        int    `json:"transaction_fee"`
	BlockReward           int    `json:"block_reward"`
	SmartContractGasLimit int    `json:"smart_contract_gas_limit"`
	AuditLogPath          string `json:"audit_log_path"`
	EncryptionKey         string `json:"encryption_key"`
}

// LoadConfig loads the configuration from a JSON file
func LoadConfig(configPath string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, errors.New("configuration file not found")
	}

	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// SaveConfig saves the configuration to a JSON file
func SaveConfig(config *Config, configPath string) error {
	configData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(configPath, configData, 0644)
}

// EncryptConfig encrypts the configuration data and saves it to a file
func EncryptConfig(config *Config, configPath, encryptionKey string) error {
	configData, err := json.Marshal(config)
	if err != nil {
		return err
	}

	encryptedData, err := encryption_utils.Encrypt(configData, encryptionKey)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(configPath, encryptedData, 0644)
}

// DecryptConfig decrypts the configuration data from a file
func DecryptConfig(configPath, encryptionKey string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, errors.New("configuration file not found")
	}

	encryptedData, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	configData, err := encryption_utils.Decrypt(encryptedData, encryptionKey)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// ValidateConfig validates the configuration parameters
func ValidateConfig(config *Config) error {
	if config.NetworkName == "" {
		return errors.New("network name is required")
	}
	if config.ConsensusAlgorithm == "" {
		return errors.New("consensus algorithm is required")
	}
	if config.MiningDifficulty <= 0 {
		return errors.New("mining difficulty must be greater than zero")
	}
	if config.TransactionFee < 0 {
		return errors.New("transaction fee cannot be negative")
	}
	if config.BlockReward <= 0 {
		return errors.New("block reward must be greater than zero")
	}
	if config.SmartContractGasLimit <= 0 {
		return errors.New("smart contract gas limit must be greater than zero")
	}
	if config.AuditLogPath == "" {
		return errors.New("audit log path is required")
	}
	if config.EncryptionKey == "" {
		return errors.New("encryption key is required")
	}

	return nil
}

// InitConfig initializes the configuration, validates it, and sets up logging
func InitConfig(configPath string) (*Config, error) {
	config, err := LoadConfig(configPath)
	if err != nil {
		logging_utils.LogError("Failed to load configuration: %v", err)
		return nil, err
	}

	if err := ValidateConfig(config); err != nil {
		logging_utils.LogError("Invalid configuration: %v", err)
		return nil, err
	}

	logging_utils.SetupLogging()

	return config, nil
}
