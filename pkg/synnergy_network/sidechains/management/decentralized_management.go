package management

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Node represents a node in the decentralized network
type Node struct {
	ID        string
	Address   string
	PublicKey string
}

// DecentralizedNetwork manages the decentralized network of nodes
type DecentralizedNetwork struct {
	nodes            map[string]*Node
	mutex            sync.Mutex
	blockchain       *Blockchain
	consensusType    ConsensusAlgorithmType
	consensusFunction func(*Block) error
}

// NewDecentralizedNetwork creates a new decentralized network
func NewDecentralizedNetwork(consensusType ConsensusAlgorithmType) *DecentralizedNetwork {
	dn := &DecentralizedNetwork{
		nodes:         make(map[string]*Node),
		blockchain:    NewBlockchain(4, consensusType),
		consensusType: consensusType,
	}
	dn.setConsensusFunction()
	return dn
}

// setConsensusFunction sets the consensus function based on the consensus type
func (dn *DecentralizedNetwork) setConsensusFunction() {
	switch dn.consensusType {
	case PoW:
		dn.consensusFunction = dn.blockchain.proofOfWork
	case PoS:
		dn.consensusFunction = dn.blockchain.proofOfStake
	case PoH:
		dn.consensusFunction = dn.blockchain.proofOfHistory
	default:
		dn.consensusFunction = dn.blockchain.proofOfWork
	}
}

// AddNode adds a new node to the decentralized network
func (dn *DecentralizedNetwork) AddNode(id, address, publicKey string) error {
	dn.mutex.Lock()
	defer dn.mutex.Unlock()

	if _, exists := dn.nodes[id]; exists {
		return errors.New("node already exists")
	}

	dn.nodes[id] = &Node{
		ID:        id,
		Address:   address,
		PublicKey: publicKey,
	}
	log.Printf("Node added: %s", id)
	return nil
}

// RemoveNode removes a node from the decentralized network
func (dn *DecentralizedNetwork) RemoveNode(id string) error {
	dn.mutex.Lock()
	defer dn.mutex.Unlock()

	if _, exists := dn.nodes[id]; !exists {
		return errors.New("node not found")
	}

	delete(dn.nodes, id)
	log.Printf("Node removed: %s", id)
	return nil
}

// GetNode returns the details of a node in the decentralized network
func (dn *DecentralizedNetwork) GetNode(id string) (*Node, error) {
	dn.mutex.Lock()
	defer dn.mutex.Unlock()

	node, exists := dn.nodes[id]
	if !exists {
		return nil, errors.New("node not found")
	}

	return node, nil
}

// GetNodes returns a list of all nodes in the decentralized network
func (dn *DecentralizedNetwork) GetNodes() []*Node {
	dn.mutex.Lock()
	defer dn.mutex.Unlock()

	nodes := make([]*Node, 0, len(dn.nodes))
	for _, node := range dn.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// BroadcastTransaction broadcasts a transaction to all nodes in the network
func (dn *DecentralizedNetwork) BroadcastTransaction(data string) {
	dn.blockchain.AddData(data)
	log.Printf("Transaction broadcasted: %s", data)
}

// ValidateNetwork validates the integrity of the network's blockchain
func (dn *DecentralizedNetwork) ValidateNetwork() error {
	return dn.blockchain.ValidateBlockchain()
}

// MineBlock mines a new block in the decentralized network
func (dn *DecentralizedNetwork) MineBlock() (*Block, error) {
	return dn.blockchain.MineBlock()
}

// SyncWithNetwork synchronizes the network's blockchain with another network's blockchain
func (dn *DecentralizedNetwork) SyncWithNetwork(other *DecentralizedNetwork) error {
	return dn.blockchain.SyncBlockchains(other.blockchain)
}

// Encryption and Decryption utilities using Argon2 and Scrypt
func Encrypt(data, passphrase string) (string, error) {
	salt := []byte("somesalt")
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(data))
	encryptedData := argon2.IDKey([]byte(data), key, 1, 64*1024, 4, 32)
	return hex.EncodeToString(encryptedData), nil
}

func Decrypt(encryptedData, passphrase string) (string, error) {
	salt := []byte("somesalt")
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	decryptedData := argon2.IDKey(data, key, 1, 64*1024, 4, 32)
	return string(decryptedData), nil
}
