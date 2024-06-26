package consensus

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Node represents a participant in the blockchain network with AI-enhanced decision capabilities
type Node struct {
	ID       uuid.UUID
	Power    int64 // Node's voting power or stake in the consensus
	IsByzantine bool
}

// NetworkSimulator represents the blockchain network simulation environment
type NetworkSimulator struct {
	Nodes       []*Node
	Blockchain  []*Block
	Latency     time.Duration // Network latency between nodes
	Mu          sync.Mutex
	BlockHeight int
}

// Block represents a single block to be added to the blockchain
type Block struct {
	Index     int
	PrevHash  string
	Timestamp time.Time
	Data      string
	Hash      string
}

// NewNetworkSimulator initializes a new simulation with specified nodes and latency
func NewNetworkSimulator(nodeCount int, latency time.Duration) *NetworkSimulator {
	ns := &NetworkSimulator{
		Nodes:    make([]*Node, nodeCount),
		Blockchain: make([]*Block, 0),
		Latency:  latency,
	}

	// Initialize nodes with random power and Byzantine trait
	for i := 0; i < nodeCount; i++ {
		ns.Nodes[i] = &Node{
			ID:    uuid.New(),
			Power: randomStake(),
			IsByzantine: (i % 10 == 0), // 10% of nodes are Byzantine
		}
	}

	return ns
}

// randomStake generates a random stake value for a node
func randomStake() int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(1000))
	return n.Int64() + 1 // Ensure at least 1
}

// SimulateConsensus runs the consensus process for the simulated network
func (ns *NetworkSimulator) SimulateConsensus(data string) {
	ns.Mu.Lock()
	defer ns.Mu.Unlock()

	block := &Block{
		Index:     len(ns.Blockchain),
		PrevHash:  getLastHash(ns.Blockchain),
		Timestamp: time.Now(),
		Data:      data,
		Hash:      "", // This would be set by a hashing function
	}

	// Simulate network latency
	time.Sleep(ns.Latency)

	// Add block to blockchain
	ns.Blockchain = append(ns.Blockchain, block)
	ns.BlockHeight++
	log.Printf("New block added by simulation: %+v", block)
}

// getLastHash retrieves the last block's hash from the blockchain
func getLastHash(bc []*Block) string {
	if len(bc) > 0 {
		return bc[len(bc)-1].Hash
	}
	return ""
}

// EncryptNodeData uses AES encryption to securely transmit node data
func EncryptNodeData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	encryptedData := aesGCM.Seal(nonce, nonce, data, nil)
	return encryptedData, nil
}

// Example usage
func main() {
	sim := NewNetworkSimulator(100, 50*time.Millisecond)
	sim.SimulateConsensus("Example transaction data")

	// Example encryption of node data
	nodeData, _ := json.Marshal(sim.Nodes[0])
	key := []byte("this_is_a_very_secure_key123")
	encryptedData, err := EncryptNodeData(nodeData, key)
	if err != nil {
		log.Fatal("Encryption error:", err)
	}

	log.Printf("Encrypted Node Data: %x", encryptedData)
}
