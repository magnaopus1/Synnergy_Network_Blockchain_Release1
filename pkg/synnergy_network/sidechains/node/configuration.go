// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// including node configuration to ensure efficient and secure network operation.
package node

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"sync"
)

// Configuration holds the configuration settings for a node.
type Configuration struct {
	NodeID           string `json:"node_id"`
	NetworkID        string `json:"network_id"`
	ListenAddress    string `json:"listen_address"`
	ConsensusAlgorithm string `json:"consensus_algorithm"`
	SecuritySettings SecuritySettings `json:"security_settings"`
	StoragePath      string `json:"storage_path"`
}

// NodeConfiguration handles the node's configuration settings.
type NodeConfiguration struct {
	config Configuration
	mutex  sync.Mutex
}

// NewNodeConfiguration creates a new NodeConfiguration instance.
func NewNodeConfiguration(configFilePath string) (*NodeConfiguration, error) {
	config, err := loadConfiguration(configFilePath)
	if err != nil {
		return nil, err
	}

	return &NodeConfiguration{
		config: config,
	}, nil
}

// loadConfiguration loads the configuration from a file.
func loadConfiguration(filePath string) (Configuration, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return Configuration{}, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return Configuration{}, err
	}

	var config Configuration
	if err := json.Unmarshal(bytes, &config); err != nil {
		return Configuration{}, err
	}

	return config, nil
}

// SaveConfiguration saves the current configuration to a file.
func (nc *NodeConfiguration) SaveConfiguration(filePath string) error {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	bytes, err := json.MarshalIndent(nc.config, "", "  ")
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(filePath, bytes, 0644); err != nil {
		return err
	}

	return nil
}

// GetNodeID returns the NodeID.
func (nc *NodeConfiguration) GetNodeID() string {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	return nc.config.NodeID
}

// SetNodeID sets the NodeID.
func (nc *NodeConfiguration) SetNodeID(nodeID string) {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	nc.config.NodeID = nodeID
}

// GetNetworkID returns the NetworkID.
func (nc *NodeConfiguration) GetNetworkID() string {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	return nc.config.NetworkID
}

// SetNetworkID sets the NetworkID.
func (nc *NodeConfiguration) SetNetworkID(networkID string) {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	nc.config.NetworkID = networkID
}

// GetListenAddress returns the ListenAddress.
func (nc *NodeConfiguration) GetListenAddress() string {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	return nc.config.ListenAddress
}

// SetListenAddress sets the ListenAddress.
func (nc *NodeConfiguration) SetListenAddress(listenAddress string) {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	nc.config.ListenAddress = listenAddress
}

// GetConsensusAlgorithm returns the ConsensusAlgorithm.
func (nc *NodeConfiguration) GetConsensusAlgorithm() string {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	return nc.config.ConsensusAlgorithm
}

// SetConsensusAlgorithm sets the ConsensusAlgorithm.
func (nc *NodeConfiguration) SetConsensusAlgorithm(consensusAlgorithm string) {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	nc.config.ConsensusAlgorithm = consensusAlgorithm
}

// GetSecuritySettings returns the SecuritySettings.
func (nc *NodeConfiguration) GetSecuritySettings() SecuritySettings {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	return nc.config.SecuritySettings
}

// SetSecuritySettings sets the SecuritySettings.
func (nc *NodeConfiguration) SetSecuritySettings(securitySettings SecuritySettings) {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	nc.config.SecuritySettings = securitySettings
}

// GetStoragePath returns the StoragePath.
func (nc *NodeConfiguration) GetStoragePath() string {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	return nc.config.StoragePath
}

// SetStoragePath sets the StoragePath.
func (nc *NodeConfiguration) SetStoragePath(storagePath string) {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	nc.config.StoragePath = storagePath
}

// ValidateConfiguration validates the current configuration settings.
func (nc *NodeConfiguration) ValidateConfiguration() error {
	nc.mutex.Lock()
	defer nc.mutex.Unlock()

	if nc.config.NodeID == "" {
		return errors.New("NodeID is required")
	}
	if nc.config.NetworkID == "" {
		return errors.New("NetworkID is required")
	}
	if nc.config.ListenAddress == "" {
		return errors.New("ListenAddress is required")
	}
	if nc.config.ConsensusAlgorithm == "" {
		return errors.New("ConsensusAlgorithm is required")
	}
	if nc.config.SecuritySettings.EncryptionAlgorithm == "" {
		return errors.New("EncryptionAlgorithm is required in SecuritySettings")
	}
	if nc.config.StoragePath == "" {
		return errors.New("StoragePath is required")
	}

	return nil
}
