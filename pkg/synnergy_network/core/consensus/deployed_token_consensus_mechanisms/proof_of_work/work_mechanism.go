package proof_of_work

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strconv"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Block represents a basic block in the blockchain.
type Block struct {
	Index     int64
	Timestamp string
	Data      string
	PrevHash  string
	Hash      string
	Nonce     int64
	Difficulty int
}

// Blockchain is a series of validated Blocks.
var Blockchain []Block

// calculateHash returns the hash of all block information.
func calculateHash(block Block) string {
	record := strconv.FormatInt(block.Index, 10) + block.Timestamp + block.Data + block.PrevHash + strconv.FormatInt(block.Nonce, 10)
	hashedBytes, _ := scrypt.Key([]byte(record), []byte(block.PrevHash), 16384, 8, 1, 32)
	return hex.EncodeToString(hashedBytes)
}

// generateBlock creates a new block using previous block's hash.
func generateBlock(oldBlock Block, Data string) (Block, error) {
	var newBlock Block

	t := time.Now()
	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.Data = Data
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Difficulty = getDifficulty(newBlock)

	for i := int64(0); ; i++ {
		newBlock.Nonce = i
		if checkHashValidity(calculateHash(newBlock), newBlock.Difficulty) {
			newBlock.Hash = calculateHash(newBlock)
			break
		}
	}

	return newBlock, nil
}

// checkHashValidity checks if the hash meets the set difficulty criteria.
func checkHashValidity(hash string, difficulty int) bool {
	const base = "0000000000000000000000000000000000000000000000000000000000000000"
	target := base[:difficulty] + hash[len(hash)-difficulty:]

	return hash < target
}

// getDifficulty adjusts the difficulty of the Proof of Work algorithm.
func getDifficulty(newBlock Block) int {
	if len(Blockchain) == 0 {
		return 1
	}
	lastBlock := Blockchain[len(Blockchain)-1]
	if newBlock.Index%10 == 0 {
		if time.Since(time.Parse(time.RFC3339, lastBlock.Timestamp)).Minutes() < 20 {
			return lastBlock.Difficulty + 1
		} else {
			return lastBlock.Difficulty - 1
		}
	}
	return lastBlock.Difficulty
}

// IsValidBlock validates that the block has the correct hash and meets the proof of work requirement.
func IsValidBlock(newBlock, oldBlock Block) bool {
	if oldBlock.Index+1 != newBlock.Index {
		return false
	}
	if oldBlock.Hash != newBlock.PrevHash {
		return false
	}
	if calculateHash(newBlock) != newBlock.Hash {
		return false
	}
	if !checkHashValidity(newBlock.Hash, newBlock.Difficulty) {
		return false
	}
	return true
}

// AddBlock adds a new block to the Blockchain after validation.
func AddBlock(newBlock Block) error {
	if IsValidBlock(newBlock, Blockchain[len(Blockchain)-1]) {
		Blockchain = append(Blockchain, newBlock)
		return nil
	}
	return errors.New("invalid block")
}
