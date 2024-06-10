package consensus

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"log"
	"sync"
)

// AIConsensus defines the structure for AI-enhanced consensus mechanisms
type AIConsensus struct {
	SecurityKey []byte
	Gossiper    GossipProtocol
	Blockchain  *Blockchain
	mutex       sync.Mutex
}

// NewAIConsensus creates a new AIConsensus instance
func NewAIConsensus(key string, gossiper GossipProtocol, blockchain *Blockchain) (*AIConsensus, error) {
	if len(key) < 32 {
		return nil, errors.New("security key must be at least 32 bytes long")
	}
	aesBlock, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	return &AIConsensus{
		SecurityKey: aesBlock,
		Gossiper:    gossiper,
		Blockchain:  blockchain,
	}, nil
}

// SecureData encrypts data using AES
func (ac *AIConsensus) SecureData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ac.SecurityKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// ValidateBlock validates a block using AI algorithms
func (ac *AIConsensus) ValidateBlock(block *Block) bool {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	// Simulate AI validation logic
	// For example, machine learning model integration could go here
	isValid := ac.Gossiper.SpreadRumour(block)
	return isValid
}

// AppendBlockToChain adds a validated block to the blockchain
func (ac *AIConsensus) AppendBlockToChain(block *Block) error {
	if !ac.ValidateBlock(block) {
		return errors.New("failed to validate block")
	}

	ac.Blockchain.AddBlock(block)
	log.Println("Block added to the chain:", block)
	return nil
}

// Mockup types for the example
type GossipProtocol interface {
	SpreadRumour(block *Block) bool
}

type Block struct {
	Hash         string
	PreviousHash string
	Timestamp    int64
	Data         []byte
}

type Blockchain struct {
	Blocks []*Block
}

func (bc *Blockchain) AddBlock(block *Block) {
	bc.Blocks = append(bc.Blocks, block)
}

// Example of how to create and use the AIConsensus
func main() {
	aiConsensus, err := NewAIConsensus("your-very-secure-key-here", NewMockGossipProtocol(), &Blockchain{})
	if err != nil {
		log.Fatal(err)
	}

	// Example block
	block := &Block{
		Hash:         "abc123",
		PreviousHash: "xyz789",
		Timestamp:    1700000000,
		Data:         []byte("Block data"),
	}

	err = aiConsensus.AppendBlockToChain(block)
	if err != nil {
		log.Println("Error appending block:", err)
	}
}

// NewMockGossipProtocol creates a mock GossipProtocol for demonstration purposes
func NewMockGossipProtocol() GossipProtocol {
	return &MockGossipProtocol{}
}

type MockGossipProtocol struct{}

func (m *MockGossipProtocol) SpreadRumour(block *Block) bool {
	// Simulate spreading a rumour and receiving consensus
	return true
}
