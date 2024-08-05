package verification

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Block represents a single block in the blockchain.
type Block struct {
	Index        int
	Timestamp    time.Time
	Data         string
	PreviousHash string
	Hash         string
	Nonce        string
}

// Blockchain represents the entire blockchain.
type Blockchain struct {
	mu    sync.Mutex
	chain []Block
}

// NewBlockchain initializes a new blockchain with a genesis block.
func NewBlockchain() *Blockchain {
	genesisBlock := Block{
		Index:     0,
		Timestamp: time.Now(),
		Data:      "Genesis Block",
		PreviousHash: "",
		Hash:      "",
		Nonce:     "",
	}
	genesisBlock.Hash = generateHash(genesisBlock)
	return &Blockchain{
		chain: []Block{genesisBlock},
	}
}

// AddBlock adds a new block to the blockchain after validation.
func (bc *Blockchain) AddBlock(data string) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	previousBlock := bc.chain[len(bc.chain)-1]
	newBlock := Block{
		Index:        previousBlock.Index + 1,
		Timestamp:    time.Now(),
		Data:         data,
		PreviousHash: previousBlock.Hash,
		Nonce:        "",
	}
	newBlock.Hash, newBlock.Nonce = generateProofOfWork(newBlock)

	if !bc.isBlockValid(newBlock, previousBlock) {
		return errors.New("invalid block")
	}

	bc.chain = append(bc.chain, newBlock)
	return nil
}

// GetBlockchain returns the entire blockchain.
func (bc *Blockchain) GetBlockchain() []Block {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	return bc.chain
}

// isBlockValid validates a new block against the previous block.
func (bc *Blockchain) isBlockValid(newBlock, previousBlock Block) bool {
	if previousBlock.Index+1 != newBlock.Index {
		return false
	}
	if previousBlock.Hash != newBlock.PreviousHash {
		return false
	}
	if generateHash(newBlock) != newBlock.Hash {
		return false
	}
	return true
}

// generateHash generates a SHA-256 hash for a block.
func generateHash(block Block) string {
	record := string(block.Index) + block.Timestamp.String() + block.Data + block.PreviousHash + block.Nonce
	hash := sha256.New()
	hash.Write([]byte(record))
	hashed := hash.Sum(nil)
	return hex.EncodeToString(hashed)
}

// generateProofOfWork generates the proof of work for a new block.
func generateProofOfWork(block Block) (string, string) {
	nonce := 0
	var hash string
	for {
		block.Nonce = string(nonce)
		hash = generateHash(block)
		if hash[:4] == "0000" { // Difficulty level
			break
		}
		nonce++
	}
	return hash, string(nonce)
}

// verifyChain verifies the entire blockchain for integrity.
func (bc *Blockchain) verifyChain() bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	for i := 1; i < len(bc.chain); i++ {
		if !bc.isBlockValid(bc.chain[i], bc.chain[i-1]) {
			return false
		}
	}
	return true
}

// performArgon2Hash performs Argon2 hashing on the input data.
func performArgon2Hash(data, salt []byte) string {
	hash := argon2.IDKey(data, salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// secureData secures the data using Argon2 hashing with a salt.
func secureData(data string) string {
	salt := generateSalt()
	hashedData := performArgon2Hash([]byte(data), salt)
	return hashedData
}

// generateSalt generates a random salt for hashing.
func generateSalt() []byte {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i) // Simplified for demonstration; replace with secure random generator
	}
	return salt
}
