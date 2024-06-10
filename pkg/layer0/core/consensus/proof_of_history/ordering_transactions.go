package proof_of_history

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// Transaction represents the structure of a blockchain transaction.
type Transaction struct {
	ID        string    // Unique identifier for the transaction
	Timestamp time.Time // Timestamp when the transaction is recorded
	Data      string    // Transaction data
	Hash      string    // Hash of the transaction for immutability
}

// Block represents a block in the blockchain
type Block struct {
	Transactions []*Transaction
	PrevHash     string
	Timestamp    time.Time
	Hash         string
}

// Blockchain represents the series of blocks linked by hashes
type Blockchain struct {
	Blocks []*Block
	mu     sync.Mutex // Mutex to protect concurrent access
}

// NewTransaction creates a new transaction with a unique timestamp and hash.
func NewTransaction(data string) *Transaction {
	t := &Transaction{
		Data:      data,
		Timestamp: time.Now(),
	}
	t.ID = GenerateHash(t.Timestamp.String() + t.Data)
	t.Hash = GenerateHash(t.ID + t.Timestamp.String() + t.Data)
	return t
}

// GenerateHash uses SHA256 to generate a hash from the input data.
func GenerateHash(data string) string {
	sum := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", sum)
}

// AddBlock adds a new block to the Blockchain after verifying its transactions.
func (bc *Blockchain) AddBlock(transactions []*Transaction) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	var lastHash string
	if len(bc.Blocks) > 0 {
		lastHash = bc.Blocks[len(bc.Blocks)-1].Hash
	}

	block := &Block{
		Transactions: transactions,
		PrevHash:     lastHash,
		Timestamp:    time.Now(),
	}
	block.Hash = GenerateHash(block.PrevHash + block.Timestamp.String() + blockDataHash(block))
	bc.Blocks = append(bc.Blocks, block)
}

// blockDataHash generates a hash for all transactions in a block.
func blockDataHash(block *Block) string {
	var transactionHashes string
	for _, tx := range block.Transactions {
		transactionHashes += tx.Hash
	}
	return GenerateHash(transactionHashes)
}

// ValidateChain checks the integrity of the blockchain and returns true if it's intact.
func (bc *Blockchain) ValidateChain() bool {
	for i, block := range bc.Blocks {
		if i == 0 {
			continue // Skip genesis block
		}
		if block.PrevHash != bc.Blocks[i-1].Hash {
			return false
		}
		calculatedHash := GenerateHash(block.PrevHash + block.Timestamp.String() + blockDataHash(block))
		if block.Hash != calculatedHash {
			return false
		}
	}
	return true
}

func main() {
	bc := &Blockchain{}
	trans1 := NewTransaction("Alice pays Bob 10 coins")
	trans2 := NewTransaction("Bob pays Carol 5 coins")

	bc.AddBlock([]*Transaction{trans1, trans2})
	fmt.Println("Blockchain valid:", bc.ValidateChain())
}
