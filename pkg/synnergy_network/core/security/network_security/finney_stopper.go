package security

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Transaction represents a blockchain transaction
type Transaction struct {
	ID        string
	Hash      string
	Signature string
	Timestamp time.Time
	Value     float64
	From      string
	To        string
}

// Block represents a single block in the blockchain
type Block struct {
	Transactions []*Transaction
	PrevHash     string
	Hash         string
	Timestamp    time.Time
}

// Blockchain is a series of validated Blocks
type Blockchain struct {
	Blocks []*Block
	lock   sync.RWMutex
}

// NewBlockchain creates a new Blockchain with the initial genesis block
func NewBlockchain() *Blockchain {
	genesisBlock := &Block{
		Timestamp: time.Now(),
	}
	genesisBlock.Hash = hashBlock(genesisBlock)

	bc := &Blockchain{}
	bc.Blocks = append(bc.Blocks, genesisBlock)
	return bc
}

// AddBlock saves the block to the blockchain
func (bc *Blockchain) AddBlock(block *Block) {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	block.PrevHash = bc.Blocks[len(bc.Blocks)-1].Hash
	block.Hash = hashBlock(block)
	bc.Blocks = append(bc.Blocks, block)
}

// ValidateTransaction checks for double spending in the Finney attack context
func (bc *Blockchain) ValidateTransaction(newTx *Transaction) error {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	for _, block := range bc.Blocks {
		for _, tx := range block.Transactions {
			if tx.ID == newTx.ID && tx.Signature == newTx.Signature {
				return errors.New("transaction has been double spent")
			}
		}
	}
	return nil
}

// hashBlock creates a hash of all block information, simulating a block hash
func hashBlock(block *Block) string {
	record := block.PrevHash + block.Timestamp.String()
	for _, tx := range block.Transactions {
		record += tx.ID + tx.Signature + tx.Timestamp.String()
	}
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return fmt.Sprintf("%x", hashed)
}

// main function to simulate transaction and block addition
func main() {
	bc := NewBlockchain()
	tx1 := &Transaction{
		ID:        "tx100",
		Signature: "sig100",
		Timestamp: time.Now(),
		Value:     100,
		From:      "Alice",
		To:        "Bob",
	}

	if err := bc.ValidateTransaction(tx1); err != nil {
		log.Fatal(err)
	}

	block := &Block{
		Timestamp:    time.Now(),
		Transactions: []*Transaction{tx1},
	}
	bc.AddBlock(block)

	fmt.Println("New block added. Blockchain length:", len(bc.Blocks))
}

