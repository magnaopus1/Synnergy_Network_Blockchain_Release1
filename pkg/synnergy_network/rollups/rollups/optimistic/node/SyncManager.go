package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Transaction represents a transaction in the rollup network.
type Transaction struct {
	ID        string
	Sender    string
	Recipient string
	Data      []byte
	Timestamp time.Time
	Signature string
}

// Block represents a block in the blockchain.
type Block struct {
	Index        int
	Timestamp    time.Time
	Transactions []*Transaction
	PrevHash     string
	Hash         string
}

// Node represents a node in the rollup network.
type Node struct {
	ID        string
	Address   string
	PublicKey string
}

// SyncManager manages the synchronization of the blockchain across nodes.
type SyncManager struct {
	Blocks      []*Block
	Nodes       []*Node
	mu          sync.Mutex
	latestIndex int
}

// NewSyncManager creates a new SyncManager.
func NewSyncManager() *SyncManager {
	return &SyncManager{
		Blocks:      []*Block{},
		Nodes:       []*Node{},
		latestIndex: 0,
	}
}

// AddNode adds a new node to the network.
func (sm *SyncManager) AddNode(node *Node) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.Nodes = append(sm.Nodes, node)
	fmt.Printf("Node %s added to the network\n", node.ID)
}

// RemoveNode removes a node from the network.
func (sm *SyncManager) RemoveNode(nodeID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for i, node := range sm.Nodes {
		if node.ID == nodeID {
			sm.Nodes = append(sm.Nodes[:i], sm.Nodes[i+1:]...)
			fmt.Printf("Node %s removed from the network\n", nodeID)
			return nil
		}
	}

	return errors.New("node not found")
}

// AddBlock adds a new block to the blockchain.
func (sm *SyncManager) AddBlock(block *Block) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if block.Index == sm.latestIndex+1 {
		sm.Blocks = append(sm.Blocks, block)
		sm.latestIndex = block.Index
		fmt.Printf("Block %d added to the blockchain\n", block.Index)
	} else {
		fmt.Printf("Block %d rejected: index out of sequence\n", block.Index)
	}
}

// SyncNodes synchronizes the blockchain with all nodes in the network.
func (sm *SyncManager) SyncNodes() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, node := range sm.Nodes {
		fmt.Printf("Synchronizing node %s\n", node.ID)
		// Implement synchronization logic with each node
	}
}

// NewTransaction creates a new transaction.
func NewTransaction(id, sender, recipient string, data []byte, signature string) *Transaction {
	return &Transaction{
		ID:        id,
		Sender:    sender,
		Recipient: recipient,
		Data:      data,
		Timestamp: time.Now(),
		Signature: signature,
	}
}

// NewBlock creates a new block.
func NewBlock(index int, transactions []*Transaction, prevHash string) *Block {
	block := &Block{
		Index:        index,
		Timestamp:    time.Now(),
		Transactions: transactions,
		PrevHash:     prevHash,
		Hash:         calculateHash(index, time.Now(), transactions, prevHash),
	}
	return block
}

// calculateHash calculates the hash for a block.
func calculateHash(index int, timestamp time.Time, transactions []*Transaction, prevHash string) string {
	record := string(index) + timestamp.String() + prevHash
	for _, tx := range transactions {
		record += tx.ID + tx.Sender + tx.Recipient + string(tx.Data) + tx.Timestamp.String()
	}

	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// EncryptTransaction encrypts transaction data using Argon2/AES.
func EncryptTransaction(tx *Transaction, key string) (string, error) {
	// Encryption logic using Argon2 and AES goes here
	return "", nil
}

// DecryptTransaction decrypts transaction data using Argon2/AES.
func DecryptTransaction(encryptedData, key string) (*Transaction, error) {
	// Decryption logic using Argon2 and AES goes here
	return nil, nil
}

// VerifyTransactionSignature verifies the signature of a transaction.
func VerifyTransactionSignature(tx *Transaction, publicKey string) bool {
	// Verification logic goes here
	return true
}
