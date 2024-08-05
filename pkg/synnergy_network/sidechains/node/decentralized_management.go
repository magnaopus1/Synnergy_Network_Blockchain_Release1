// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// including decentralized management of node operations.
package node

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Node represents a blockchain node with decentralized management capabilities.
type Node struct {
	ID                 string
	Peers              map[string]*Peer
	Blockchain         *Blockchain
	mutex              sync.Mutex
	encryptionKey      []byte
	consensusAlgorithm ConsensusAlgorithm
}

// Peer represents a peer node in the network.
type Peer struct {
	ID      string
	Address string
}

// Blockchain represents the blockchain maintained by the node.
type Blockchain struct {
	Blocks []*Block
	mutex  sync.Mutex
}

// Block represents a single block in the blockchain.
type Block struct {
	Index     int
	Timestamp string
	Data      string
	PrevHash  string
	Hash      string
}

// ConsensusAlgorithm defines the interface for consensus algorithms.
type ConsensusAlgorithm interface {
	ProposeBlock(*Node, *Block) error
	ValidateBlock(*Node, *Block) error
	ReachConsensus(*Node) error
}

// NewNode creates a new Node instance.
func NewNode(id string, encryptionKey string, consensusAlgorithm ConsensusAlgorithm) (*Node, error) {
	key, err := deriveKey(encryptionKey)
	if err != nil {
		return nil, err
	}

	return &Node{
		ID:                 id,
		Peers:              make(map[string]*Peer),
		Blockchain:         &Blockchain{Blocks: []*Block{}},
		encryptionKey:      key,
		consensusAlgorithm: consensusAlgorithm,
	}, nil
}

// deriveKey derives a key from the given passphrase using scrypt.
func deriveKey(passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
}

// Encrypt encrypts data using AES-GCM.
func (n *Node) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(n.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-GCM.
func (n *Node) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(n.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// AddPeer adds a new peer to the network.
func (n *Node) AddPeer(peerID, address string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.Peers[peerID] = &Peer{ID: peerID, Address: address}
}

// RemovePeer removes a peer from the network.
func (n *Node) RemovePeer(peerID string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	delete(n.Peers, peerID)
}

// GetPeers returns the list of peers in the network.
func (n *Node) GetPeers() map[string]*Peer {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.Peers
}

// ProposeBlock proposes a new block to be added to the blockchain.
func (n *Node) ProposeBlock(data string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	lastBlock := n.Blockchain.Blocks[len(n.Blockchain.Blocks)-1]
	newBlock := &Block{
		Index:     lastBlock.Index + 1,
		Timestamp: time.Now().String(),
		Data:      data,
		PrevHash:  lastBlock.Hash,
		Hash:      calculateHash(lastBlock.Index+1, time.Now().String(), data, lastBlock.Hash),
	}

	return n.consensusAlgorithm.ProposeBlock(n, newBlock)
}

// ValidateBlock validates the proposed block.
func (n *Node) ValidateBlock(block *Block) error {
	return n.consensusAlgorithm.ValidateBlock(n, block)
}

// ReachConsensus reaches a consensus on the proposed block.
func (n *Node) ReachConsensus() error {
	return n.consensusAlgorithm.ReachConsensus(n)
}

// calculateHash calculates the hash of the block.
func calculateHash(index int, timestamp, data, prevHash string) string {
	record := fmt.Sprintf("%d%s%s%s", index, timestamp, data, prevHash)
	hash := sha256.Sum256([]byte(record))
	return fmt.Sprintf("%x", hash)
}

// AddBlock adds a new block to the blockchain.
func (n *Node) AddBlock(block *Block) {
	n.Blockchain.mutex.Lock()
	defer n.Blockchain.mutex.Unlock()
	n.Blockchain.Blocks = append(n.Blockchain.Blocks, block)
}

// GetBlockchain returns the blockchain.
func (n *Node) GetBlockchain() []*Block {
	n.Blockchain.mutex.Lock()
	defer n.Blockchain.mutex.Unlock()
	return n.Blockchain.Blocks
}

// encodeBlock encodes a Block into bytes using JSON encoding.
func encodeBlock(block *Block) ([]byte, error) {
	return json.Marshal(block)
}

// decodeBlock decodes bytes into a Block using JSON encoding.
func decodeBlock(data []byte) (*Block, error) {
	var block Block
	err := json.Unmarshal(data, &block)
	if err != nil {
		return nil, err
	}
	return &block, nil
}
