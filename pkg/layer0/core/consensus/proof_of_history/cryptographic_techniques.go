package proof_of_history

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/synthron/synthronchain/utils"
)

// Transaction represents a single transaction with its timestamp and hash
type Transaction struct {
	Data      string
	Timestamp int64
	Hash      string
}

// Block represents a block in the blockchain with cryptographic links
type Block struct {
	PreviousHash string
	Timestamp    int64
	Transactions []*Transaction
	Hash         string
}

// CryptographicAnchor represents a periodic anchor point for validating transaction history
type CryptographicAnchor struct {
	Hash      string
	Timestamp int64
}

// GenerateTransactionHash uses SHA-256 to hash the transaction data with a timestamp
func GenerateTransactionHash(data string, timestamp int64) string {
	record := data + string(timestamp)
	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// NewTransaction creates a new transaction with a unique timestamp and hash
func NewTransaction(data string) *Transaction {
	timestamp := time.Now().UnixNano()
	hash := GenerateTransactionHash(data, timestamp)
	return &Transaction{
		Data:      data,
		Timestamp: timestamp,
		Hash:      hash,
	}
}

// AddTransaction adds a new transaction to the block
func (b *Block) AddTransaction(transaction *Transaction) {
	b.Transactions = append(b.Transactions, transaction)
	b.Hash = b.generateBlockHash() // Update block hash whenever a new transaction is added
}

// generateBlockHash generates a cryptographic hash of the entire block
func (b *Block) generateBlockHash() string {
	var transactionHashes string
	for _, tx := range b.Transactions {
		transactionHashes += tx.Hash
	}
	record := b.PreviousHash + transactionHashes + string(b.Timestamp)
	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// CreateCryptographicAnchor generates a new anchor for PoH validation
func CreateCryptographicAnchor(previousAnchor *CryptographicAnchor, block *Block) *CryptographicAnchor {
	// Combine the previous anchor with the current block's hash
	data := previousAnchor.Hash + block.Hash
	hash := sha256.Sum256([]byte(data))
	return &CryptographicAnchor{
		Hash:      hex.EncodeToString(hash[:]),
		Timestamp: time.Now().UnixNano(),
	}
}

// InitializeBlockchain sets up the initial state of the blockchain with a genesis block
func InitializeBlockchain() *Block {
	genesisBlock := &Block{
		PreviousHash: "0",
		Timestamp:    time.Now().UnixNano(),
	}
	genesisBlock.Hash = genesisBlock.generateBlockHash()
	return genesisBlock
}

func main() {
	blockchain := InitializeBlockchain()
	transaction := NewTransaction("Genesis Transaction")
	blockchain.AddTransaction(transaction)

	// Example of creating a cryptographic anchor
	anchor := CreateCryptographicAnchor(&CryptographicAnchor{Hash: "initial-anchor", Timestamp: time.Now().UnixNano()}, blockchain)
	println("New Anchor Created: ", anchor.Hash)
}
