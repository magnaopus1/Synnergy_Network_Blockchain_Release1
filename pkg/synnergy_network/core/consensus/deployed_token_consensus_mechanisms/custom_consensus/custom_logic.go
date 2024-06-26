package custom_consensus

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/synthron_blockchain/crypto"
)

// ConsensusRule defines the structure for custom rules in the consensus mechanism.
type ConsensusRule struct {
	MinTransaction  int       `json:"min_transaction"`
	BlockSizeLimit  int       `json:"block_size_limit"`
	BlockTimeInterval time.Duration `json:"block_time_interval"`
}

// ConsensusBlock represents a block in the blockchain under this custom consensus.
type ConsensusBlock struct {
	PreviousHash string    `json:"previous_hash"`
	Transactions []string  `json:"transactions"`
	Timestamp    time.Time `json:"timestamp"`
	Nonce        int       `json:"nonce"`
}

// BlockData holds the data necessary to form a block.
type BlockData struct {
	Transactions []string
	TimeCreated  time.Time
}

// CreateBlock generates a new block for the blockchain using the custom consensus rules.
func CreateBlock(previousBlock ConsensusBlock, blockData BlockData, rule ConsensusRule) (ConsensusBlock, error) {
	if len(blockData.Transactions) < rule.MinTransaction {
		return ConsensusBlock{}, errors.New("not enough transactions to create a block")
	}

	block := ConsensusBlock{
		PreviousHash: calculateHash(previousBlock),
		Transactions: blockData.Transactions,
		Timestamp:    blockData.TimeCreated,
	}

	nonce, err := findValidNonce(block, rule)
	if err != nil {
		return ConsensusBlock{}, err
	}

	block.Nonce = nonce
	return block, nil
}

// findValidNonce tries to find a nonce that satisfies the block's hash requirement under the given rules.
func findValidNonce(block ConsensusBlock, rule ConsensusRule) (int, error) {
	nonce := 0
	for {
		block.Nonce = nonce
		hash := calculateHash(block)
		if isValidHash(hash, rule.BlockSizeLimit) {
			return nonce, nil
		}
		nonce++
		if nonce > 1e6 { // To prevent infinite loops in case of an error in logic
			return 0, errors.New("could not find a valid nonce after 1,000,000 attempts")
		}
	}
}

// calculateHash generates a hash for a block using SHA-256.
func calculateHash(block ConsensusBlock) string {
	blockBytes, _ := json.Marshal(block)
	hash := sha256.Sum256(blockBytes)
	return string(hash[:])
}

// isValidHash checks if the hash of the block is under the specified limit.
func isValidHash(hash string, limit int) bool {
	// This function would implement the actual hash checking logic based on block size or other criteria
	return len(hash) < limit
}

// EncryptData encrypts data using the specified algorithm (Scrypt, AES, Argon2)
func EncryptData(data []byte, key []byte) ([]byte, error) {
	// Utilize Argon2 for encryption as it offers better security properties for the given use case
	encryptedData, err := crypto.Argon2Encrypt(data, key)
	if err != nil {
	return nil, err
	}
	return encryptedData, nil
}

// add more innovative functions and methods based on specific needs and technologies
