package proof_of_history

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/synthron/synthronchain/storage"
)

// Block represents a single block in the blockchain
type Block struct {
	PreviousHash string
	Timestamp    int64
	Transactions []string
	Hash         string
}

// Blockchain represents the state of the blockchain with all committed blocks
type Blockchain struct {
	Blocks []*Block
}

// NewBlock creates a new block using the previous block's hash and current transactions
func NewBlock(previousHash string, transactions []string) *Block {
	block := &Block{
		PreviousHash: previousHash,
		Timestamp:    time.Now().UnixNano(),
		Transactions: transactions,
	}
	block.Hash = block.generateHash()
	return block
}

// generateHash generates a cryptographic hash of the block's contents
func (b *Block) generateHash() string {
	record := b.PreviousHash + string(b.Timestamp) + hex.EncodeToString([]byte(string(b.Transactions)))
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

// AddBlock adds a new block to the blockchain after validation
func (bc *Blockchain) AddBlock(newBlock *Block) bool {
	if bc.validateBlock(newBlock) {
		bc.Blocks = append(bc.Blocks, newBlock)
		return true
	}
	return false
}

// validateBlock checks if the block can be added to the blockchain
func (bc *Blockchain) validateBlock(block *Block) bool {
	lastBlock := bc.Blocks[len(bc.Blocks)-1]
	if lastBlock.Hash != block.PreviousHash {
		return false
	}
	if !bc.verifyPoH(block) {
		return false
	}
	return true
}

// verifyPoH verifies the Proof of History for a block
func (bc *Blockchain) verifyPoH(block *Block) bool {
	expectedHash := block.generateHash()
	return expectedHash == block.Hash
}

// InitializeBlockchain initializes the blockchain with a genesis block
func InitializeBlockchain() *Blockchain {
	genesisBlock := NewBlock("0", []string{"Genesis Block"})
	return &Blockchain{Blocks: []*Block{genesisBlock}}
}

// Simulate the block creation and propagation
func main() {
	blockchain := InitializeBlockchain()

	// Simulating transaction data
	transactions := []string{"tx1", "tx2", "tx3"}

	// Creating and adding a new block
	newBlock := NewBlock(blockchain.Blocks[len(blockchain.Blocks)-1].Hash, transactions)
	if blockchain.AddBlock(newBlock) {
		println("New block added successfully. Block Hash:", newBlock.Hash)
	} else {
		println("Failed to add new block.")
	}
}
