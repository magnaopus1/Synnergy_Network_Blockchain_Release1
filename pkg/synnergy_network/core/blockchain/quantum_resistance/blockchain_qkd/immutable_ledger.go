package blockchain_qkd

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network/crypto"
	"github.com/synnergy_network/utils"
)

// ImmutableLedger represents the structure for managing an immutable ledger of quantum key transactions
type ImmutableLedger struct {
	mu              sync.Mutex
	ledger          map[string]LedgerEntry
	blockchain      []Block
	currentBlock    Block
	blockSize       int
	transactionPool []Transaction
}

// LedgerEntry represents a single entry in the immutable ledger
type LedgerEntry struct {
	KeyID     string
	Timestamp time.Time
	Action    string
	Key       string
}

// Block represents a block in the blockchain
type Block struct {
	Index        int
	Timestamp    time.Time
	Transactions []Transaction
	PrevHash     string
	Hash         string
}

// Transaction represents a single transaction in the blockchain
type Transaction struct {
	KeyID     string
	Timestamp time.Time
	Action    string
	Key       string
}

// NewImmutableLedger creates a new instance of ImmutableLedger
func NewImmutableLedger(blockSize int) *ImmutableLedger {
	return &ImmutableLedger{
		ledger:     make(map[string]LedgerEntry),
		blockchain: []Block{},
		blockSize:  blockSize,
	}
}

// AddEntry adds a new entry to the ledger and blockchain
func (il *ImmutableLedger) AddEntry(entry LedgerEntry) error {
	il.mu.Lock()
	defer il.mu.Unlock()

	if _, exists := il.ledger[entry.KeyID]; exists && entry.Action == "add" {
		return errors.New("keyID already exists")
	}

	if entry.Action == "revoke" {
		if _, exists := il.ledger[entry.KeyID]; !exists {
			return errors.New("keyID does not exist for revocation")
		}
	}

	il.ledger[entry.KeyID] = entry
	transaction := Transaction{
		KeyID:     entry.KeyID,
		Timestamp: entry.Timestamp,
		Action:    entry.Action,
		Key:       entry.Key,
	}
	il.transactionPool = append(il.transactionPool, transaction)

	if len(il.transactionPool) >= il.blockSize {
		il.createBlock()
	}

	return nil
}

// createBlock creates a new block and adds it to the blockchain
func (il *ImmutableLedger) createBlock() {
	var prevHash string
	if len(il.blockchain) == 0 {
		prevHash = ""
	} else {
		prevHash = il.blockchain[len(il.blockchain)-1].Hash
	}

	block := Block{
		Index:        len(il.blockchain),
		Timestamp:    time.Now(),
		Transactions: il.transactionPool,
		PrevHash:     prevHash,
	}
	block.Hash = il.calculateHash(block)
	il.blockchain = append(il.blockchain, block)
	il.transactionPool = []Transaction{}
	il.currentBlock = block
}

// calculateHash calculates the hash of a block
func (il *ImmutableLedger) calculateHash(block Block) string {
	record := fmt.Sprintf("%d%s%s%s", block.Index, block.Timestamp, block.Transactions, block.PrevHash)
	hash := sha256.New()
	hash.Write([]byte(record))
	return hex.EncodeToString(hash.Sum(nil))
}

// GetBlockchain returns the current blockchain
func (il *ImmutableLedger) GetBlockchain() []Block {
	il.mu.Lock()
	defer il.mu.Unlock()
	return il.blockchain
}

// ValidateBlockchain validates the integrity of the blockchain
func (il *ImmutableLedger) ValidateBlockchain() error {
	il.mu.Lock()
	defer il.mu.Unlock()

	for i, block := range il.blockchain {
		if i > 0 && block.PrevHash != il.blockchain[i-1].Hash {
			return errors.New("blockchain integrity check failed")
		}
		if block.Hash != il.calculateHash(block) {
			return errors.New("block hash mismatch")
		}
	}
	return nil
}

// Example usage of ImmutableLedger
func ExampleImmutableLedger() {
	ledger := NewImmutableLedger(5)
	entry1 := LedgerEntry{
		KeyID:     "key1",
		Timestamp: time.Now(),
		Action:    "add",
		Key:       "exampleQuantumKey1",
	}
	ledger.AddEntry(entry1)

	entry2 := LedgerEntry{
		KeyID:     "key2",
		Timestamp: time.Now(),
		Action:    "add",
		Key:       "exampleQuantumKey2",
	}
	ledger.AddEntry(entry2)

	fmt.Println("Current Blockchain:", ledger.GetBlockchain())

	if err := ledger.ValidateBlockchain(); err != nil {
		fmt.Println("Blockchain validation failed:", err)
	} else {
		fmt.Println("Blockchain validated successfully")
	}
}

// quantumKeyDistribution manages the lifecycle of quantum keys
func quantumKeyDistribution() {
	ledger := NewImmutableLedger(10)
	km := NewKeyManager(24 * time.Hour)

	// Generate and distribute a new quantum-resistant key
	keyID := "exampleKeyID"
	key, err := km.GenerateQuantumKey(keyID)
	if err != nil {
		fmt.Println("Error generating quantum key:", err)
		return
	}

	entry := LedgerEntry{
		KeyID:     keyID,
		Timestamp: time.Now(),
		Action:    "add",
		Key:       key,
	}
	if err := ledger.AddEntry(entry); err != nil {
		fmt.Println("Error adding entry to ledger:", err)
		return
	}

	// Revoke the key after some time
	time.Sleep(5 * time.Second)
	if err := km.RevokeKey(keyID); err != nil {
		fmt.Println("Error revoking key:", err)
		return
	}

	entry = LedgerEntry{
		KeyID:     keyID,
		Timestamp: time.Now(),
		Action:    "revoke",
		Key:       key,
	}
	if err := ledger.AddEntry(entry); err != nil {
		fmt.Println("Error adding revocation entry to ledger:", err)
		return
	}

	fmt.Println("Current Blockchain:", ledger.GetBlockchain())

	if err := ledger.ValidateBlockchain(); err != nil {
		fmt.Println("Blockchain validation failed:", err)
	} else {
		fmt.Println("Blockchain validated successfully")
	}
}

// main function demonstrating full lifecycle management of quantum keys and the immutable ledger
func main() {
	ExampleImmutableLedger()
	quantumKeyDistribution()
}

