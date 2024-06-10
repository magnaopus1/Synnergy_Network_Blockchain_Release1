package node_deployment

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"

	"golang.org/x/crypto/argon2"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// Configurations structure
type Configurations struct {
	NodeName       string
	NodeDir        string
	SmartContract  string
	NetworkConfig  string
	EncryptionSalt string
}

// LocalSetupManager handles local deployment operations
type LocalSetupManager struct {
	Config Configurations
}

// NewLocalSetupManager initializes a new LocalSetupManager
func NewLocalSetupManager(configFile string) (*LocalSetupManager, error) {
	var config Configurations

	// Find home directory.
	home, err := homedir.Dir()
	if err != nil {
		return nil, err
	}

	// Search config in home directory with name ".synthron" (without extension).
	viper.AddConfigPath(home)
	viper.SetConfigName(".synthron")
	viper.SetConfigType("json")

	if err := viper.ReadInConfig(); err != nil {
		return nil, errors.Wrap(err, "failed to read config file")
	}

	if err := viper.Unmarshal(&config); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal config")
	}

	return &LocalSetupManager{Config: config}, nil
}

// DeployNode sets up a blockchain node locally
func (lsm *LocalSetupManager) DeployNode() error {
	log.Printf("Deploying node %s...", lsm.Config.NodeName)
	err := os.MkdirAll(lsm.Config.NodeDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create node directory: %v", err)
	}

	cmd := exec.Command("blockchain-node", "--config", lsm.Config.NetworkConfig)
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to deploy node: %v", err)
	}
	log.Printf("Node %s deployed successfully.", lsm.Config.NodeName)
	return nil
}

// DeploySmartContract deploys a smart contract to the local node
func (lsm *LocalSetupManager) DeploySmartContract() error {
	log.Printf("Deploying smart contract from %s...", lsm.Config.SmartContract)

	cmd := exec.Command("blockchain-cli", "deploy", "--contract", lsm.Config.SmartContract)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to deploy smart contract: %v", err)
	}
	log.Printf("Smart contract deployed successfully.")
	return nil
}

// InitializeNetwork initializes the blockchain network with specified parameters
func (lsm *LocalSetupManager) InitializeNetwork() error {
	log.Printf("Initializing network with config %s...", lsm.Config.NetworkConfig)

	cmd := exec.Command("blockchain-cli", "init", "--config", lsm.Config.NetworkConfig)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to initialize network: %v", err)
	}
	log.Printf("Network initialized successfully.")
	return nil
}

// SecureConfiguration secures sensitive configuration data using Argon2
func (lsm *LocalSetupManager) SecureConfiguration(data []byte) ([]byte, error) {
	log.Printf("Securing configuration data...")

	salt := []byte(lsm.Config.EncryptionSalt)
	hashedData := argon2.IDKey(data, salt, 1, 64*1024, 4, 32)
	return hashedData, nil
}

// Main function for demonstration
func main() {
	configFile := "/path/to/config.json"
	localManager, err := NewLocalSetupManager(configFile)
	if err != nil {
		log.Fatalf("Failed to initialize Local Setup Manager: %v", err)
	}

	err = localManager.DeployNode()
	if err != nil {
		log.Fatalf("Failed to deploy node: %v", err)
	}

	err = localManager.DeploySmartContract()
	if err != nil {
		log.Fatalf("Failed to deploy smart contract: %v", err)
	}

	err = localManager.InitializeNetwork()
	if err != nil {
		log.Fatalf("Failed to initialize network: %v", err)
	}

	// Example data to secure
	data := []byte("sensitive-configuration-data")
	securedData, err := localManager.SecureConfiguration(data)
	if err != nil {
		log.Fatalf("Failed to secure configuration data: %v", err)
	}
	log.Printf("Secured configuration data: %x", securedData)
}
