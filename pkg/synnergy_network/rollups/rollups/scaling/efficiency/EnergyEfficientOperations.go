package efficiency

import (
	"log"
	"sync"
	"time"

	"crypto/sha256"
	"encoding/hex"
	"math"
)

// Block represents a single block in the blockchain.
type Block struct {
	Index        int
	Timestamp    int64
	PreviousHash string
	Hash         string
	Data         string
	Nonce        int
	Difficulty   int
}

// Blockchain represents the entire chain of blocks.
type Blockchain struct {
	blocks []*Block
	mu     sync.Mutex
}

// NewBlockchain initializes a new blockchain with a genesis block.
func NewBlockchain() *Blockchain {
	genesisBlock := &Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		PreviousHash: "",
		Hash:         calculateHash(0, time.Now().Unix(), "", "", 0),
		Data:         "Genesis Block",
		Nonce:        0,
		Difficulty:   2,
	}
	return &Blockchain{
		blocks: []*Block{genesisBlock},
	}
}

// AddBlock adds a new block to the blockchain.
func (bc *Blockchain) AddBlock(data string) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	previousBlock := bc.blocks[len(bc.blocks)-1]
	newBlock := bc.mineBlock(previousBlock, data)
	bc.blocks = append(bc.blocks, newBlock)
	log.Printf("Block %d added to the blockchain.\n", newBlock.Index)
}

// mineBlock mines a new block using a proof-of-work mechanism.
func (bc *Blockchain) mineBlock(previousBlock *Block, data string) *Block {
	index := previousBlock.Index + 1
	timestamp := time.Now().Unix()
	previousHash := previousBlock.Hash
	difficulty := bc.adjustDifficulty(previousBlock)

	var nonce int
	var hash string

	for {
		hash = calculateHash(index, timestamp, previousHash, data, nonce)
		if isValidHash(hash, difficulty) {
			break
		}
		nonce++
	}

	return &Block{
		Index:        index,
		Timestamp:    timestamp,
		PreviousHash: previousHash,
		Hash:         hash,
		Data:         data,
		Nonce:        nonce,
		Difficulty:   difficulty,
	}
}

// calculateHash calculates the hash of a block.
func calculateHash(index int, timestamp int64, previousHash, data string, nonce int) string {
	record := string(index) + string(timestamp) + previousHash + data + string(nonce)
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

// isValidHash checks if a hash meets the required difficulty.
func isValidHash(hash string, difficulty int) bool {
	prefix := ""
	for i := 0; i < difficulty; i++ {
		prefix += "0"
	}
	return hash[:difficulty] == prefix
}

// GetBlocks returns the current blocks in the blockchain.
func (bc *Blockchain) GetBlocks() []*Block {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return bc.blocks
}

// adjustDifficulty adjusts the mining difficulty based on the time taken to mine the previous block.
func (bc *Blockchain) adjustDifficulty(previousBlock *Block) int {
	expectedTimePerBlock := 10 * time.Second // 10 seconds per block
	actualTime := time.Now().Unix() - previousBlock.Timestamp
	if actualTime < int64(expectedTimePerBlock.Seconds()) {
		return previousBlock.Difficulty + 1
	} else if actualTime > int64(expectedTimePerBlock.Seconds()) {
		return int(math.Max(float64(previousBlock.Difficulty-1), 1))
	}
	return previousBlock.Difficulty
}

// optimizeEnergyUsage optimizes the energy usage by adjusting mining parameters.
func (bc *Blockchain) optimizeEnergyUsage() {
	log.Println("Optimizing energy usage...")
	// Placeholder for energy optimization logic, such as dynamically adjusting difficulty, reducing resource-intensive operations, etc.
	for _, block := range bc.blocks {
		// Example: Reduce difficulty if the average block time is significantly higher than expected
		if block.Difficulty > 1 && block.Timestamp > time.Now().Unix()-20 {
			block.Difficulty--
		}
	}
}

func main() {
	// Initialize blockchain
	bc := NewBlockchain()

	// Add blocks to the blockchain
	bc.AddBlock("First block data")
	bc.AddBlock("Second block data")

	// Optimize energy usage
	bc.optimizeEnergyUsage()

	// Output the blockchain
	for _, block := range bc.GetBlocks() {
		log.Printf("Index: %d, Timestamp: %d, PreviousHash: %s, Hash: %s, Data: %s, Nonce: %d, Difficulty: %d\n",
			block.Index, block.Timestamp, block.PreviousHash, block.Hash, block.Data, block.Nonce, block.Difficulty)
	}
}
