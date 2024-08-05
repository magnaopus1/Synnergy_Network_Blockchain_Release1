// Package node_configuration provides tools for configuring the nodes in the Synnergy Network.
package node_configuration

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
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v2"
)

// NodeConfig represents the configuration for a single node in the Synnergy Network.
type NodeConfig struct {
	NodeID           string `yaml:"node_id"`
	NetworkID        string `yaml:"network_id"`
	ConsensusType    string `yaml:"consensus_type"`
	StakeAmount      int    `yaml:"stake_amount"`
	ValidatorAddress string `yaml:"validator_address"`
	PrivateKey       string `yaml:"private_key"`
	PublicKey        string `yaml:"public_key"`
	GenesisTime      time.Time `yaml:"genesis_time"`
}

// Validate checks if the node configuration is valid.
func (config *NodeConfig) Validate() error {
	if config.NodeID == "" {
		return errors.New("NodeID cannot be empty")
	}
	if config.NetworkID == "" {
		return errors.New("NetworkID cannot be empty")
	}
	if config.ConsensusType == "" {
		return errors.New("ConsensusType cannot be empty")
	}
	if config.StakeAmount <= 0 {
		return errors.New("StakeAmount must be greater than zero")
	}
	if config.ValidatorAddress == "" {
		return errors.New("ValidatorAddress cannot be empty")
	}
	if config.PrivateKey == "" {
		return errors.New("PrivateKey cannot be empty")
	}
	if config.PublicKey == "" {
		return errors.New("PublicKey cannot be empty")
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

// LoadNodeConfig loads the node configuration from a YAML file.
func LoadNodeConfig(path string) (*NodeConfig, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read node configuration file: %v", err)
	}

	var config NodeConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal node configuration: %v", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid node configuration: %v", err)
	}

	return &config, nil
}

// SaveNodeConfig saves the node configuration to a YAML file.
func SaveNodeConfig(config *NodeConfig, path string) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid node configuration: %v", err)
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal node configuration: %v", err)
	}

	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write node configuration file: %v", err)
	}

	return nil
}

// InitializeNodeConfig initializes a new node configuration with default values.
func InitializeNodeConfig(nodeID, networkID, consensusType, validatorAddress string, stakeAmount int, genesisTime time.Time) *NodeConfig {
	// Generate public and private keys (for demonstration purposes, we'll use dummy keys here)
	privateKey := generatePrivateKey(nodeID)
	publicKey := generatePublicKey(privateKey)

	return &NodeConfig{
		NodeID:           nodeID,
		NetworkID:        networkID,
		ConsensusType:    consensusType,
		StakeAmount:      stakeAmount,
		ValidatorAddress: validatorAddress,
		PrivateKey:       privateKey,
		PublicKey:        publicKey,
		GenesisTime:      genesisTime,
	}
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

// SetupNode sets up the node with the given configuration.
func SetupNode(config *NodeConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	nodePath := filepath.Join("./nodes", config.NodeID)
	if err := os.MkdirAll(nodePath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create node directory: %v", err)
	}

	configFilePath := filepath.Join(nodePath, "config.yaml")
	if err := SaveNodeConfig(config, configFilePath); err != nil {
		return fmt.Errorf("failed to save node configuration: %v", err)
	}

	cmd := exec.Command("start_node", configFilePath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start node process: %v", err)
	}
	return nil
}

// setupMultipleNodes sets up multiple nodes concurrently.
func setupMultipleNodes(configs []*NodeConfig) error {
	var wg sync.WaitGroup
	for _, config := range configs {
		wg.Add(1)
		go func(conf *NodeConfig) {
			defer wg.Done()
			if err := SetupNode(conf); err != nil {
				fmt.Printf("failed to set up node %s: %v\n", conf.NodeID, err)
			}
		}(config)
	}
	wg.Wait()
	return nil
}

// Example of setting up a node using the above functionalities.
func SetupNodeExample() {
	networkID := "synnergy_testnet_1"
	consensusType := "PoS"
	validatorAddress := "validator1_address"
	stakeAmount := 1000
	genesisTime := time.Now()

	nodeConfig := InitializeNodeConfig("node1", networkID, consensusType, validatorAddress, stakeAmount, genesisTime)

	if err := SetupNode(nodeConfig); err != nil {
		fmt.Printf("Error setting up node: %v\n", err)
		return
	}

	loadedConfig, err := LoadNodeConfig("./nodes/node1/config.yaml")
	if err != nil {
		fmt.Printf("Error loading node configuration: %v\n", err)
		return
	}

	fmt.Printf("Loaded Node Configuration: %+v\n", loadedConfig)
}
