package on_premise

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/viper"
	"golang.org/x/crypto/argon2"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
)

// Configurations structure
type Configurations struct {
	NodeName       string
	NodeDir        string
	SmartContract  string
	NetworkConfig  string
	EncryptionSalt string
}

// ServerConfigurationManager handles on-premise server deployment operations
type ServerConfigurationManager struct {
	Config Configurations
}

// NewServerConfigurationManager initializes a new ServerConfigurationManager
func NewServerConfigurationManager(configFile string) (*ServerConfigurationManager, error) {
	var config Configurations

	// Find home directory
	home, err := homedir.Dir()
	if err != nil {
		return nil, err
	}

	// Search config in home directory with name ".synthron" (without extension)
	viper.AddConfigPath(home)
	viper.SetConfigName(".synthron")
	viper.SetConfigType("json")

	if err := viper.ReadInConfig(); err != nil {
		return nil, errors.Wrap(err, "failed to read config file")
	}

	if err := viper.Unmarshal(&config); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal config")
	}

	return &ServerConfigurationManager{Config: config}, nil
}

// DeployNode sets up a blockchain node on an on-premise server
func (scm *ServerConfigurationManager) DeployNode() error {
	log.Printf("Deploying node %s...", scm.Config.NodeName)
	err := os.MkdirAll(scm.Config.NodeDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create node directory: %v", err)
	}

	cmd := exec.Command("blockchain-node", "--config", scm.Config.NetworkConfig)
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to deploy node: %v", err)
	}
	log.Printf("Node %s deployed successfully.", scm.Config.NodeName)
	return nil
}

// DeploySmartContract deploys a smart contract to the on-premise node
func (scm *ServerConfigurationManager) DeploySmartContract() error {
	log.Printf("Deploying smart contract from %s...", scm.Config.SmartContract)

	cmd := exec.Command("blockchain-cli", "deploy", "--contract", scm.Config.SmartContract)
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
func (scm *ServerConfigurationManager) InitializeNetwork() error {
	log.Printf("Initializing network with config %s...", scm.Config.NetworkConfig)

	cmd := exec.Command("blockchain-cli", "init", "--config", scm.Config.NetworkConfig)
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
func (scm *ServerConfigurationManager) SecureConfiguration(data []byte) ([]byte, error) {
	log.Printf("Securing configuration data...")

	salt := []byte(scm.Config.EncryptionSalt)
	hashedData := argon2.IDKey(data, salt, 1, 64*1024, 4, 32)
	return hashedData, nil
}

// Main function for demonstration
func main() {
	configFile := "/path/to/config.json"
	serverManager, err := NewServerConfigurationManager(configFile)
	if err != nil {
		log.Fatalf("Failed to initialize Server Configuration Manager: %v", err)
	}

	err = serverManager.DeployNode()
	if err != nil {
		log.Fatalf("Failed to deploy node: %v", err)
	}

	err = serverManager.DeploySmartContract()
	if err != nil {
		log.Fatalf("Failed to deploy smart contract: %v", err)
	}

	err = serverManager.InitializeNetwork()
	if err != nil {
		log.Fatalf("Failed to initialize network: %v", err)
	}

	// Example data to secure
	data := []byte("sensitive-configuration-data")
	securedData, err := serverManager.SecureConfiguration(data)
	if err != nil {
		log.Fatalf("Failed to secure configuration data: %v", err)
	}
	log.Printf("Secured configuration data: %x", securedData)
}
