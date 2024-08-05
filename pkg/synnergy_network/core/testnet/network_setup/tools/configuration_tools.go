// Package tools provides various tools for configuring and managing the Synnergy Network.
package tools

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sync"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v2"
)

// NetworkConfig represents the configuration for the entire Synnergy Network.
type NetworkConfig struct {
	NetworkID      string `yaml:"network_id"`
	BlockTime      int    `yaml:"block_time"`
	EpochDuration  int    `yaml:"epoch_duration"`
	StakeThreshold int    `yaml:"stake_threshold"`
	MaxValidators  int    `yaml:"max_validators"`
	MinValidators  int    `yaml:"min_validators"`
	ConsensusType  string `yaml:"consensus_type"`
	EncryptionKey  string `yaml:"encryption_key"`
	InitialNodes   []NodeConfig `yaml:"initial_nodes"`
}

// NodeConfig represents the configuration for a single node in the Synnergy Network.
type NodeConfig struct {
	NodeID           string `yaml:"node_id"`
	ValidatorAddress string `yaml:"validator_address"`
	PrivateKey       string `yaml:"private_key"`
	PublicKey        string `yaml:"public_key"`
	StakeAmount      int    `yaml:"stake_amount"`
}

// Validate checks if the network configuration is valid.
func (config *NetworkConfig) Validate() error {
	if config.NetworkID == "" {
		return errors.New("NetworkID cannot be empty")
	}
	if config.BlockTime <= 0 {
		return errors.New("BlockTime must be greater than zero")
	}
	if config.EpochDuration <= 0 {
		return errors.New("EpochDuration must be greater than zero")
	}
	if config.StakeThreshold < 0 {
		return errors.New("StakeThreshold cannot be negative")
	}
	if config.MaxValidators <= 0 {
		return errors.New("MaxValidators must be greater than zero")
	}
	if config.MinValidators <= 0 || config.MinValidators > config.MaxValidators {
		return errors.New("MinValidators must be greater than zero and less than or equal to MaxValidators")
	}
	if config.ConsensusType == "" {
		return errors.New("ConsensusType cannot be empty")
	}
	if config.EncryptionKey == "" {
		return errors.New("EncryptionKey cannot be empty")
	}
	return nil
}

// Encrypt encrypts the given data using AES encryption with the provided key.
func Encrypt(key, text string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(text), nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given data using AES decryption with the provided key.
func Decrypt(key, cryptoText string) (string, error) {
	data, err := hex.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// LoadNetworkConfig loads the network configuration from a YAML file.
func LoadNetworkConfig(path string) (*NetworkConfig, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read network configuration file: %v", err)
	}

	var config NetworkConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal network configuration: %v", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid network configuration: %v", err)
	}

	return &config, nil
}

// SaveNetworkConfig saves the network configuration to a YAML file.
func SaveNetworkConfig(config *NetworkConfig, path string) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid network configuration: %v", err)
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal network configuration: %v", err)
	}

	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write network configuration file: %v", err)
	}

	return nil
}

// InitializeNetworkConfig initializes a new network configuration with default values.
func InitializeNetworkConfig() *NetworkConfig {
	encryptionKey := generateEncryptionKey()

	return &NetworkConfig{
		NetworkID:      "synnergy_testnet_1",
		BlockTime:      10,
		EpochDuration:  1000,
		StakeThreshold: 1000,
		MaxValidators:  100,
		MinValidators:  10,
		ConsensusType:  "PoS",
		EncryptionKey:  encryptionKey,
		InitialNodes:   []NodeConfig{},
	}
}

// generateEncryptionKey generates a secure encryption key.
func generateEncryptionKey() string {
	salt := make([]byte, 16)
	rand.Read(salt)
	key := argon2.Key([]byte("synnergy_network"), salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(key)
}

// AddNodeConfig adds a new node configuration to the network configuration.
func (config *NetworkConfig) AddNodeConfig(nodeID, validatorAddress string, stakeAmount int) error {
	privateKey := generatePrivateKey(nodeID)
	publicKey := generatePublicKey(privateKey)

	nodeConfig := NodeConfig{
		NodeID:           nodeID,
		ValidatorAddress: validatorAddress,
		PrivateKey:       privateKey,
		PublicKey:        publicKey,
		StakeAmount:      stakeAmount,
	}

	config.InitialNodes = append(config.InitialNodes, nodeConfig)
	return nil
}

// generatePrivateKey generates a dummy private key based on the node ID.
func generatePrivateKey(nodeID string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := argon2.Key([]byte(nodeID), salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// generatePublicKey generates a dummy public key based on the private key.
func generatePublicKey(privateKey string) string {
	// In a real implementation, this would involve actual public key cryptography.
	return fmt.Sprintf("%s_pub", privateKey)
}

// SetupNodes sets up the initial nodes based on the network configuration.
func (config *NetworkConfig) SetupNodes() error {
	var wg sync.WaitGroup
	for _, node := range config.InitialNodes {
		wg.Add(1)
		go func(n NodeConfig) {
			defer wg.Done()
			if err := setupNode(n, config.EncryptionKey); err != nil {
				fmt.Printf("failed to set up node %s: %v\n", n.NodeID, err)
			}
		}(node)
	}
	wg.Wait()
	return nil
}

// setupNode sets up a single node based on its configuration.
func setupNode(config NodeConfig, encryptionKey string) error {
	nodePath := filepath.Join("./nodes", config.NodeID)
	if err := os.MkdirAll(nodePath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create node directory: %v", err)
	}

	encryptedPrivateKey, err := Encrypt(encryptionKey, config.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %v", err)
	}
	config.PrivateKey = encryptedPrivateKey

	configFilePath := filepath.Join(nodePath, "config.yaml")
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal node configuration: %v", err)
	}

	if err := ioutil.WriteFile(configFilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write node configuration file: %v", err)
	}

	cmd := exec.Command("start_node", configFilePath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start node process: %v", err)
	}
	return nil
}

// UpdateNetworkConfig updates the network configuration in the specified file.
func UpdateNetworkConfig(path string, updates map[string]interface{}) error {
	config, err := LoadNetworkConfig(path)
	if err != nil {
		return err
	}

	for key, value := range updates {
		switch key {
		case "block_time":
			config.BlockTime = value.(int)
		case "epoch_duration":
			config.EpochDuration = value.(int)
		case "stake_threshold":
			config.StakeThreshold = value.(int)
		case "max_validators":
			config.MaxValidators = value.(int)
		case "min_validators":
			config.MinValidators = value.(int)
		case "consensus_type":
			config.ConsensusType = value.(string)
		case "encryption_key":
			config.EncryptionKey = value.(string)
		case "initial_nodes":
			config.InitialNodes = value.([]NodeConfig)
		default:
			return fmt.Errorf("unknown parameter: %s", key)
		}
	}

	return SaveNetworkConfig(config, path)
}

// PrintNetworkConfig prints the network configuration in a human-readable format.
func PrintNetworkConfig(config *NetworkConfig) {
	fmt.Printf("Network Configuration:\n")
	fmt.Printf("  Network ID:      %s\n", config.NetworkID)
	fmt.Printf("  Block Time:      %d seconds\n", config.BlockTime)
	fmt.Printf("  Epoch Duration:  %d blocks\n", config.EpochDuration)
	fmt.Printf("  Stake Threshold: %d\n", config.StakeThreshold)
	fmt.Printf("  Max Validators:  %d\n", config.MaxValidators)
	fmt.Printf("  Min Validators:  %d\n", config.MinValidators)
	fmt.Printf("  Consensus Type:  %s\n", config.ConsensusType)
	fmt.Printf("  Encryption Key:  %s\n", config.EncryptionKey)
	fmt.Printf("  Initial Nodes:   %+v\n", config.InitialNodes)
}

// Example of configuring the network using the above functionalities
func ConfigureNetworkExample() {
	configPath := "./network_config.yaml"

	// Initialize default network configuration
	defaultConfig := InitializeNetworkConfig()

	// Add initial nodes to the network configuration
	defaultConfig.AddNodeConfig("node1", "validator1_address", 1000)
	defaultConfig.AddNodeConfig("node2", "validator2_address", 2000)

	// Save the default configuration to a file
	if err := SaveNetworkConfig(defaultConfig, configPath); err != nil {
		fmt.Printf("Error saving network configuration: %v\n", err)
		return
	}

	// Load the configuration from the file
	config, err := LoadNetworkConfig(configPath)
	if err != nil {
		fmt.Printf("Error loading network configuration: %v\n", err)
		return
	}

	// Print the loaded configuration
	PrintNetworkConfig(config)

	// Setup initial nodes
	if err := config.SetupNodes(); err != nil {
		fmt.Printf("Error setting up nodes: %v\n", err)
		return
	}

	// Update specific configuration parameters
	updates := map[string]interface{}{
		"block_time":     5,
		"max_validators": 200,
	}
	if err := UpdateNetworkConfig(configPath, updates); err != nil {
		fmt.Printf("Error updating network configuration: %v\n", err)
		return
	}

	// Print the updated configuration
	updatedConfig, err := LoadNetworkConfig(configPath)
	if err != nil {
		fmt.Printf("Error reloading network configuration: %v\n", err)
		return
	}
	PrintNetworkConfig(updatedConfig)
}
