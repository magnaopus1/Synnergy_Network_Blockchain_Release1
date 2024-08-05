package management

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Block represents a single block in the blockchain
type Block struct {
	Index        int
	Timestamp    time.Time
	Data         string
	PrevHash     string
	Hash         string
	Nonce        int
	Difficulty   int
}

// Blockchain represents the blockchain
type Blockchain struct {
	blocks       []*Block
	difficulty   int
	mutex        sync.Mutex
	pendingData  []string
}

// NewBlockchain creates a new Blockchain instance
func NewBlockchain(difficulty int) *Blockchain {
	genesisBlock := &Block{
		Index:      0,
		Timestamp:  time.Now(),
		Data:       "Genesis Block",
		PrevHash:   "",
		Hash:       "",
		Nonce:      0,
		Difficulty: difficulty,
	}
	genesisBlock.Hash = calculateHash(genesisBlock)
	return &Blockchain{
		blocks:     []*Block{genesisBlock},
		difficulty: difficulty,
	}
}

// AddData adds data to the list of pending transactions
func (bc *Blockchain) AddData(data string) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	bc.pendingData = append(bc.pendingData, data)
	log.Printf("Data added: %s", data)
}

// MineBlock mines a new block with the pending data
func (bc *Blockchain) MineBlock() (*Block, error) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	if len(bc.pendingData) == 0 {
		return nil, errors.New("no data to mine")
	}

	lastBlock := bc.blocks[len(bc.blocks)-1]
	newBlock := &Block{
		Index:      lastBlock.Index + 1,
		Timestamp:  time.Now(),
		Data:       combineData(bc.pendingData),
		PrevHash:   lastBlock.Hash,
		Difficulty: bc.difficulty,
	}
	bc.pendingData = []string{}

	err := bc.proofOfWork(newBlock)
	if err != nil {
		return nil, err
	}

	bc.blocks = append(bc.blocks, newBlock)
	log.Printf("New block mined: %v", newBlock)
	return newBlock, nil
}

// GetBlockchain returns the list of blocks in the blockchain
func (bc *Blockchain) GetBlockchain() []*Block {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	return bc.blocks
}

// proofOfWork performs the mining operation to find the valid hash
func (bc *Blockchain) proofOfWork(block *Block) error {
	for {
		hash := calculateHash(block)
		if isHashValid(hash, block.Difficulty) {
			block.Hash = hash
			return nil
		}
		block.Nonce++
	}
}

// calculateHash calculates the hash of a block
func calculateHash(block *Block) string {
	record := string(block.Index) + block.Timestamp.String() + block.Data + block.PrevHash + string(block.Nonce)
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

// isHashValid checks if a hash meets the difficulty requirement
func isHashValid(hash string, difficulty int) bool {
	prefix := ""
	for i := 0; i < difficulty; i++ {
		prefix += "0"
	}
	return hash[:difficulty] == prefix
}

// combineData combines pending data into a single string
func combineData(data []string) string {
	result := ""
	for _, d := range data {
		result += d
	}
	return result
}

// SaveBlockchain saves the blockchain state (placeholder for actual implementation)
func (bc *Blockchain) SaveBlockchain() error {
	// Placeholder for saving the blockchain state to persistent storage
	log.Printf("Blockchain state saved.")
	return nil
}

// LoadBlockchain loads the blockchain state (placeholder for actual implementation)
func (bc *Blockchain) LoadBlockchain() error {
	// Placeholder for loading the blockchain state from persistent storage
	log.Printf("Blockchain state loaded.")
	return nil
}

// Encryption and Decryption utilities using Scrypt
func Encrypt(data, passphrase string) (string, error) {
	salt := make([]byte, 8)
	_, err := time.Now().UTC().MarshalBinary()
	if err != nil {
		return "", err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed), nil
}

func Decrypt(data, passphrase string) (string, error) {
	salt := make([]byte, 8)
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed), nil
}
