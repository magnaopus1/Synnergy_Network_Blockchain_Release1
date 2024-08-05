// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// including node initialization for real-world use.
package node

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Node represents a blockchain node with initialization capabilities.
type Node struct {
	ID              string
	Address         string
	PrivateKey      string
	PublicKey       string
	Peers           map[string]*Peer
	mutex           sync.Mutex
	Initialization  Initialization
	Configuration   Configuration
}

// Peer represents a peer node in the network.
type Peer struct {
	ID      string
	Address string
	Load    int
}

// Initialization holds the initialization data for a node.
type Initialization struct {
	Timestamp     time.Time
	GenesisBlock  string
}

// Configuration holds the configuration data for a node.
type Configuration struct {
	MaxLoad           int
	ScalingThreshold  int
	ScalingFactor     int
	ScalingCooldown   time.Duration
}

// NewNode creates a new Node instance with specified parameters.
func NewNode(id, address, privateKey, publicKey string) *Node {
	return &Node{
		ID:            id,
		Address:       address,
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		Peers:         make(map[string]*Peer),
		Initialization: Initialization{},
		Configuration:  Configuration{},
	}
}

// InitializeNode initializes the node with genesis block and timestamp.
func (n *Node) InitializeNode(genesisBlock string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.Initialization.Timestamp = time.Now()
	n.Initialization.GenesisBlock = genesisBlock
	fmt.Printf("Node %s initialized with genesis block: %s\n", n.ID, genesisBlock)
}

// GenerateKeys generates a public-private key pair for the node.
func (n *Node) GenerateKeys() error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		return err
	}

	n.PrivateKey = privateKey
	n.PublicKey = publicKey
	fmt.Printf("Generated keys for node %s\n", n.ID)
	return nil
}

// generateKeyPair generates a public-private key pair using Scrypt for key derivation.
func generateKeyPair() (string, string, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return "", "", err
	}

	privateKeyBytes, err := scrypt.Key([]byte("password"), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", "", err
	}

	privateKey := hex.EncodeToString(privateKeyBytes)
	hash := sha256.New()
	hash.Write(privateKeyBytes)
	publicKey := hex.EncodeToString(hash.Sum(nil))

	return privateKey, publicKey, nil
}

// SaveNodeState saves the node's state to a file.
func (n *Node) SaveNodeState(filePath string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	state := fmt.Sprintf("Node ID: %s\nAddress: %s\nPrivateKey: %s\nPublicKey: %s\nTimestamp: %s\nGenesisBlock: %s\n",
		n.ID, n.Address, n.PrivateKey, n.PublicKey, n.Initialization.Timestamp, n.Initialization.GenesisBlock)
	_, err = file.WriteString(state)
	if err != nil {
		return err
	}

	fmt.Printf("Node state saved to %s\n", filePath)
	return nil
}

// LoadNodeState loads the node's state from a file.
func (n *Node) LoadNodeState(filePath string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var state string
	_, err = fmt.Fscanf(file, "Node ID: %s\nAddress: %s\nPrivateKey: %s\nPublicKey: %s\nTimestamp: %s\nGenesisBlock: %s\n",
		&n.ID, &n.Address, &n.PrivateKey, &n.PublicKey, &n.Initialization.Timestamp, &n.Initialization.GenesisBlock)
	if err != nil {
		return err
	}

	fmt.Printf("Node state loaded from %s\n", filePath)
	return nil
}

// ValidateGenesisBlock validates the genesis block of the node.
func (n *Node) ValidateGenesisBlock(genesisBlock string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.Initialization.GenesisBlock != genesisBlock {
		return errors.New("invalid genesis block")
	}

	fmt.Printf("Genesis block validated for node %s\n", n.ID)
	return nil
}

// InitializeNodeFromConfig initializes the node with configuration data.
func (n *Node) InitializeNodeFromConfig(config Configuration) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.Configuration = config
	fmt.Printf("Node %s initialized with configuration: %+v\n", n.ID, config)
}

// Example usage:
// func main() {
// 	node := NewNode("node-1", "address-1", "", "")
// 	node.GenerateKeys()
// 	node.InitializeNode("genesis-block-1")
// 	node.SaveNodeState("node_state.txt")
// 	node.LoadNodeState("node_state.txt")
// 	node.ValidateGenesisBlock("genesis-block-1")
// }

