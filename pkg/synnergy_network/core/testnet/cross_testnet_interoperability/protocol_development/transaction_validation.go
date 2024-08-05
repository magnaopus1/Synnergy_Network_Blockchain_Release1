package protocol_development

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

// Transaction represents a blockchain transaction
type Transaction struct {
	ID            string
	Sender        string
	Receiver      string
	Amount        float64
	Timestamp     time.Time
	Signature     string
	PreviousHash  string
	CurrentHash   string
}

// Block represents a block in the blockchain
type Block struct {
	Index        int
	Transactions []Transaction
	Timestamp    time.Time
	PrevHash     string
	Hash         string
	Nonce        string
}

// Blockchain represents the entire chain
type Blockchain struct {
	Chain  []Block
	Length int
}

// ValidateTransaction checks the validity of a transaction
func ValidateTransaction(tx Transaction, publicKey string, signature string) (bool, error) {
	// Validate transaction fields
	if tx.Sender == "" || tx.Receiver == "" || tx.Amount <= 0 {
		return false, errors.New("invalid transaction fields")
	}

	// Validate signature (Placeholder, implement actual signature verification)
	if subtle.ConstantTimeCompare([]byte(tx.Signature), []byte(signature)) != 1 {
		return false, errors.New("invalid transaction signature")
	}

	// Verify sender has sufficient balance (Placeholder, actual implementation needed)
	// if !hasSufficientBalance(tx.Sender, tx.Amount) {
	// 	return false, errors.New("insufficient balance")
	// }

	return true, nil
}

// ValidateBlock checks the validity of a block
func ValidateBlock(block Block, prevBlock Block) (bool, error) {
	// Check index
	if block.Index != prevBlock.Index+1 {
		return false, errors.New("invalid block index")
	}

	// Check previous hash
	if block.PrevHash != prevBlock.Hash {
		return false, errors.New("invalid previous hash")
	}

	// Validate transactions in the block
	for _, tx := range block.Transactions {
		if valid, err := ValidateTransaction(tx, "", ""); !valid || err != nil {
			return false, fmt.Errorf("invalid transaction: %v", err)
		}
	}

	// Validate block hash
	if block.Hash != calculateHash(block) {
		return false, errors.New("invalid block hash")
	}

	return true, nil
}

// CalculateHash calculates the hash of a block
func calculateHash(block Block) string {
	record := fmt.Sprintf("%d%s%s%s%s", block.Index, block.Timestamp, block.PrevHash, block.Nonce, block.Transactions)
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

// AddBlock adds a block to the blockchain after validation
func (bc *Blockchain) AddBlock(newBlock Block) error {
	if bc.Length == 0 {
		bc.Chain = append(bc.Chain, newBlock)
		bc.Length++
		return nil
	}

	lastBlock := bc.Chain[bc.Length-1]
	if valid, err := ValidateBlock(newBlock, lastBlock); !valid || err != nil {
		return fmt.Errorf("failed to add block: %v", err)
	}

	bc.Chain = append(bc.Chain, newBlock)
	bc.Length++
	return nil
}

// ProofOfWork implements a simple proof of work algorithm
func ProofOfWork(block Block, difficulty int) (Block, error) {
	prefix := ""
	for i := 0; i < difficulty; i++ {
		prefix += "0"
	}

	for {
		hash := calculateHash(block)
		if hash[:difficulty] == prefix {
			block.Hash = hash
			return block, nil
		}

		block.Nonce = uuid.New().String()
	}
}

// CreateGenesisBlock creates the first block in the blockchain
func CreateGenesisBlock() Block {
	genesisTransaction := Transaction{
		ID:        uuid.New().String(),
		Sender:    "0",
		Receiver:  "0",
		Amount:    0,
		Timestamp: time.Now(),
	}

	genesisBlock := Block{
		Index:        0,
		Transactions: []Transaction{genesisTransaction},
		Timestamp:    time.Now(),
		PrevHash:     "0",
		Nonce:        uuid.New().String(),
	}

	genesisBlock.Hash = calculateHash(genesisBlock)
	return genesisBlock
}

// InitializeBlockchain initializes a new blockchain with the genesis block
func InitializeBlockchain() *Blockchain {
	genesisBlock := CreateGenesisBlock()
	return &Blockchain{
		Chain:  []Block{genesisBlock},
		Length: 1,
	}
}

// Encrypt encrypts data using Argon2
func Encrypt(data, salt string) (string, error) {
	hash := argon2.IDKey([]byte(data), []byte(salt), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash), nil
}

// Decrypt decrypts data using Argon2 (Note: Argon2 is not typically used for decryption, only hashing)
func Decrypt(hash, salt string) (string, error) {
	return "", errors.New("Argon2 is a one-way hash function, not suitable for decryption")
}
