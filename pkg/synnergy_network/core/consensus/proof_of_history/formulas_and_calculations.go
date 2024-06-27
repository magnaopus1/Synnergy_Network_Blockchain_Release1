package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"time"
)

// PoHCalculator handles the generation of hashes and timestamps for transactions.
type PoHCalculator struct {
	Seed         string
	CurrentHash  string
	LastBlockHash string
	BlockInterval time.Duration
}

// NewPoHCalculator initializes a PoH calculator with a seed for the hash chain.
func NewPoHCalculator(seed string) *PoHCalculator {
	return &PoHCalculator{
		Seed:         seed,
		CurrentHash:  seed,
		LastBlockHash: "",
		BlockInterval: 10 * time.Second, // Default interval between blocks.
	}
}

// GenerateNextHash produces a new hash based on the current hash, using SHA-256.
func (p *PoHCalculator) GenerateNextHash(transaction string) string {
	data := p.CurrentHash + transaction
	hash := sha256.Sum256([]byte(data))
	p.CurrentHash = hex.EncodeToString(hash[:])
	return p.CurrentHash
}

// CalculateHashChain generates a chain of hashes for a slice of transactions.
func (p *PoHCalculator) CalculateHashChain(transactions []string) []string {
	var hashList []string
	for _, transaction := range transactions {
		hash := p.GenerateNextHash(transaction)
		hashList = append(hashList, hash)
	}
	return hashList
}

// ValidateHashChain checks the integrity of a chain of transaction hashes.
func (p *PoHCalculator) ValidateHashChain(transactions []string, expectedHashes []string) bool {
	for i, transaction := range transactions {
		hash := p.GenerateNextHash(transaction)
		if hash != expectedHashes[i] {
			return false
		}
	}
	return true
}

// AnchorTimestampsToBlocks links transaction timestamps to specific blockchain blocks.
func (p *PoHCalculator) AnchorTimestampsToBlocks(timestamps []time.Time) []big.Int {
	var blockNumbers []big.Int
	for _, timestamp := range timestamps {
		blockNumber := big.NewInt(0)
		blockNumber.SetUint64(uint64(timestamp.UnixNano() / int64(p.BlockInterval)))
		blockNumbers = append(blockNumbers, *blockNumber)
	}
	return blockNumbers
}

// UpdateBlockInterval dynamically adjusts the interval between blocks based on network conditions.
func (p *PoHCalculator) UpdateBlockInterval(newInterval time.Duration) {
	p.BlockInterval = newInterval
}

