package management

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// ConsensusAlgorithmType defines the type of consensus algorithm
type ConsensusAlgorithmType int

const (
	PoW ConsensusAlgorithmType = iota
	PoS
	PoH
)

// Block represents a single block in the blockchain
type Block struct {
	Index      int
	Timestamp  time.Time
	Data       string
	PrevHash   string
	Hash       string
	Nonce      int
	Difficulty int
}

// Blockchain represents the blockchain
type Blockchain struct {
	blocks            []*Block
	difficulty        int
	mutex             sync.Mutex
	pendingData       []string
	consensusType     ConsensusAlgorithmType
	consensusFunction func(*Block) error
}

// NewBlockchain creates a new Blockchain instance
func NewBlockchain(difficulty int, consensusType ConsensusAlgorithmType) *Blockchain {
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

	bc := &Blockchain{
		blocks:        []*Block{genesisBlock},
		difficulty:    difficulty,
		consensusType: consensusType,
	}

	bc.setConsensusFunction()
	return bc
}

// setConsensusFunction sets the consensus function based on the consensus type
func (bc *Blockchain) setConsensusFunction() {
	switch bc.consensusType {
	case PoW:
		bc.consensusFunction = bc.proofOfWork
	case PoS:
		bc.consensusFunction = bc.proofOfStake
	case PoH:
		bc.consensusFunction = bc.proofOfHistory
	default:
		bc.consensusFunction = bc.proofOfWork
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

	err := bc.consensusFunction(newBlock)
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

// proofOfStake is a placeholder for PoS consensus algorithm implementation
func (bc *Blockchain) proofOfStake(block *Block) error {
	// Placeholder: Implement proof of stake logic
	block.Hash = calculateHash(block)
	return nil
}

// proofOfHistory is a placeholder for PoH consensus algorithm implementation
func (bc *Blockchain) proofOfHistory(block *Block) error {
	// Placeholder: Implement proof of history logic
	block.Hash = calculateHash(block)
	return nil
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

// SyncBlockchains synchronizes this blockchain with another blockchain
func (bc *Blockchain) SyncBlockchains(other *Blockchain) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	other.mutex.Lock()
	defer other.mutex.Unlock()

	if len(other.blocks) == 0 {
		return errors.New("other blockchain is empty")
	}

	lastIndex := bc.blocks[len(bc.blocks)-1].Index
	if lastIndex >= other.blocks[len(other.blocks)-1].Index {
		return nil // No need to sync, this blockchain is already ahead or in sync
	}

	for _, block := range other.blocks {
		if block.Index > lastIndex {
			bc.blocks = append(bc.blocks, block)
		}
	}

	log.Printf("Blockchain synchronized. Current block count: %d", len(bc.blocks))
	return nil
}

// ValidateBlockchain validates the integrity of the blockchain
func (bc *Blockchain) ValidateBlockchain() error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	for i := 1; i < len(bc.blocks); i++ {
		prevBlock := bc.blocks[i-1]
		currBlock := bc.blocks[i]

		if currBlock.PrevHash != prevBlock.Hash {
			return errors.New("blockchain is invalid: mismatched previous hash")
		}

		if !isHashValid(currBlock.Hash, currBlock.Difficulty) {
			return errors.New("blockchain is invalid: invalid hash")
		}

		if currBlock.Hash != calculateHash(currBlock) {
			return errors.New("blockchain is invalid: hash does not match calculated hash")
		}
	}

	log.Printf("Blockchain validated successfully. Block count: %d", len(bc.blocks))
	return nil
}

// Encryption and Decryption utilities using Argon2 and Scrypt
func Encrypt(data, passphrase string) (string, error) {
	salt := []byte("somesalt")
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256([]byte(data))
	encryptedData := argon2.IDKey([]byte(data), key, 1, 64*1024, 4, 32)
	return hex.EncodeToString(encryptedData), nil
}

func Decrypt(encryptedData, passphrase string) (string, error) {
	salt := []byte("somesalt")
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	decryptedData := argon2.IDKey(data, key, 1, 64*1024, 4, 32)
	return string(decryptedData), nil
}
