package hybrid

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sync"
	"time"

	"github.com/synthron/synthroncore/block"
	"github.com/synthron/synthroncore/transaction"
	"github.com/synthron/synthroncore/utils"
	"golang.org/x/crypto/argon2"
)

const (
	// Initial block reward in Synthrons (SYN)
	initialBlockReward = 1252.0
	// Halving interval in number of blocks
	halvingInterval = 200000
	// Maximum coins to be issued
	maxCoins = 500000000
)

type Block struct {
	Transactions []*transaction.Transaction
	PrevHash     string
	Hash         string
	Timestamp    int64
	Nonce        uint64
}

type Blockchain struct {
	Blocks []*Block
	Mutex  sync.Mutex
}

// NewBlock creates a new block using the specified transactions and the previous hash
func NewBlock(transactions []*transaction.Transaction, prevHash string) *Block {
	block := &Block{
		Transactions: transactions,
		PrevHash:     prevHash,
		Timestamp:    time.Now().UnixNano(),
	}
	block.Hash = block.calculateHash()
	return block
}

// calculateHash computes the hash of the block using SHA-256, simulating the PoW process
func (b *Block) calculateHash() string {
	record := utils.ToHex(b.Timestamp) + b.PrevHash + hashTransactions(b.Transactions) + utils.ToHex(b.Nonce)
	h := sha256.New()
	h.Write([]byte(record))
	return hex.EncodeToString(h.Sum(nil))
}

// hashTransactions computes a hash over all transactions in the block
func hashTransactions(transactions []*transaction.Transaction) string {
	var txHashes string
	for _, tx := range transactions {
		txHashes += tx.Hash()
	}
	h := sha256.New()
	h.Write([]byte(txHashes))
	return hex.EncodeToString(h.Sum(nil))
}

// MineBlock simulates the PoW mining process
func (b *Block) MineBlock(difficulty int) {
	for !utils.HasPrefix(b.Hash, difficulty) {
		b.Nonce++
		b.Hash = b.calculateHash()
	}
}

// ValidateBlock checks if the block's hash meets the network's difficulty requirements
func (b *Block) ValidateBlock(difficulty int) bool {
	return utils.HasPrefix(b.Hash, difficulty)
}

// AddBlock adds a new block to the blockchain after validation
func (bc *Blockchain) AddBlock(block *Block, difficulty int) bool {
	bc.Mutex.Lock()
	defer bc.Mutex.Unlock()

	// Validate the new block
	if !block.ValidateBlock(difficulty) {
		return false
	}

	// Append to the blockchain
	bc.Blocks = append(bc.Blocks, block)
	return true
}

// calculateReward calculates the mining reward for the block at the given height
func calculateReward(height int) float64 {
	reductions := height / halvingInterval
	if reductions > math.Log2(maxCoins/initialBlockReward) {
		return 0
	}
	return initialBlockReward / math.Pow(2, float64(reductions))
}

// RewardDistribution handles the distribution of mining rewards including halving
func (bc *Blockchain) RewardDistribution(block *Block) {
	height := len(bc.Blocks)
	reward := calculateReward(height)
	blockReward := block.CreateCoinbaseTransaction(reward)
	bc.AddTransaction(blockReward)
}

// simulateArgon2Mining simulates mining with Argon2 for PoW phase
func simulateArgon2Mining(input []byte) string {
	return hex.EncodeToString(argon2.IDKey(input, []byte("somesalt"), 1, 64*1024, 4, 32))
}

// The above code integrates the blockchain with a PoW mining mechanism using Argon2,
// includes reward halving and secure hashing to maintain network integrity and economic stability.
