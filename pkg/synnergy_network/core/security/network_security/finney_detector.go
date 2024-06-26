package security

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	Salt      = "choose-a-strong-random-salt"
	HashMem   = 64 * 1024
	HashTime  = 1
	HashKeyLen = 32
)

// Transaction defines the structure of a blockchain transaction
type Transaction struct {
	ID        string
	Hash      string
	Timestamp time.Time
	Value     float64
	From      string
	To        string
	Signature string
}

// Block represents a single block in the blockchain
type Block struct {
	Transactions []*Transaction
	PrevHash     string
	Hash         string
	Timestamp    time.Time
}

// Blockchain manages a sequence of blocks
type Blockchain struct {
	Blocks []*Block
	lock   sync.RWMutex
}

// NewBlockchain initializes a blockchain with a genesis block
func NewBlockchain() *Blockchain {
	genesisBlock := &Block{
		Timestamp: time.Now(),
	}
	genesisBlock.Hash = hashBlock(genesisBlock)

	return &Blockchain{
		Blocks: []*Block{genesisBlock},
	}
}

// AddBlock adds a new block to the chain
func (bc *Blockchain) AddBlock(block *Block) {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	block.PrevHash = bc.Blocks[len(bc.Blocks)-1].Hash
	block.Hash = hashBlock(block)
	bc.Blocks = append(bc.Blocks, block)
}

// DetectFinneyAttack identifies potential Finney attacks by verifying the uniqueness of transaction hashes
func (bc *Blockchain) DetectFinneyAttack(tx *Transaction) error {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	for _, block := range bc.Blocks {
		for _, transaction := range block.Transactions {
			if transaction.Hash == tx.Hash && transaction.Signature != tx.Signature {
				return errors.New("potential Finney attack detected")
			}
		}
	}
	return nil
}

// hashBlock generates a hash for the block
func hashBlock(block *Block) string {
	record := block.PrevHash + block.Timestamp.String()
	for _, tx := range block.Transactions {
		record += tx.Hash + tx.Signature
	}
	h := sha256.New()
	h.Write([]byte(record))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// argonHash uses Argon2 to create a hash from the transaction data
func argonHash(data []byte) string {
	return fmt.Sprintf("%x", argon2.IDKey(data, []byte(Salt), HashTime, HashMem, 4, HashKeyLen))
}

func main() {
	bc := NewBlockchain()
	tx := &Transaction{
		ID:        "tx1001",
		Timestamp: time.Now(),
		From:      "Alice",
		To:        "Bob",
		Value:     100,
		Signature: "AliceSignature",
	}
	tx.Hash = argonHash([]byte(tx.ID + tx.Signature))

	if err := bc.DetectFinneyAttack(tx); err != nil {
		log.Fatal(err)
	}

	block := &Block{
		Timestamp:    time.Now(),
		Transactions: []*Transaction{tx},
	}
	bc.AddBlock(block)

	fmt.Println("Blockchain operation successful. Length:", len(bc.Blocks))
}
