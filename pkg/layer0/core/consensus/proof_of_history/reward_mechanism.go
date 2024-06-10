package proof_of_history

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// Constants for reward calculations.
const (
	baseReward     = 10    // Base reward for block validation
	transactionFee = 0.01  // Fee per transaction included in a block
)

// Validator represents a node that can validate transactions and create blocks.
type Validator struct {
	ID         string  // Unique identifier for the validator
	Stake      float64 // Amount of coin staked
	TotalStake float64 // Total staked amount in the network for weight calculation
}

// Block represents a blockchain block.
type Block struct {
	Transactions []*Transaction
	Validator    *Validator
	Timestamp    time.Time
	Hash         string
	Reward       float64
}

// Transaction encapsulates details of a blockchain transaction.
type Transaction struct {
	Data      string
	Timestamp time.Time
}

// GenerateHash computes a SHA-256 hash for block and transaction identifiers.
func GenerateHash(data string) string {
	hashBytes := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hashBytes)
}

// CalculateReward determines the reward for a validator based on block and transaction metrics.
func CalculateReward(block *Block) float64 {
	// Reward based on the number of transactions and the base reward
	numTransactions := len(block.Transactions)
	reward := baseReward + (transactionFee * float64(numTransactions))

	// Additional reward based on stake ratio if applicable
	stakeRatio := block.Validator.Stake / block.Validator.TotalStake
	reward += reward * stakeRatio

	return reward
}

// CreateBlock simulates block creation by a validator.
func (v *Validator) CreateBlock(transactions []*Transaction) *Block {
	block := &Block{
		Transactions: transactions,
		Validator:    v,
		Timestamp:    time.Now(),
	}

	// Generate a unique hash for the block
	blockData := fmt.Sprintf("%v-%v", v.ID, block.Timestamp)
	block.Hash = GenerateHash(blockData)

	// Calculate the reward for the block
	block.Reward = CalculateReward(block)

	return block
}

// Blockchain represents the entire chain of blocks validated by different validators.
type Blockchain struct {
	Blocks []*Block
	mu     sync.Mutex
}

// AddBlock adds a new block to the blockchain.
func (bc *Blockchain) AddBlock(block *Block) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	bc.Blocks = append(bc.Blocks, block)
	fmt.Printf("Block added by Validator %s: Reward %.2f\n", block.Validator.ID, block.Reward)
}

func main() {
	// Example initialization and operation
	blockchain := &Blockchain{}
	validator := &Validator{ID: "Validator1", Stake: 1500, TotalStake: 10000}

	// Simulate transaction processing
	transactions := []*Transaction{
		{Data: "Alice pays Bob 5 coins", Timestamp: time.Now()},
		{Data: "Charlie pays Dana 3 coins", Timestamp: time.Now()},
	}
	block := validator.CreateBlock(transactions)

	// Add block to blockchain
	blockchain.AddBlock(block)
}
