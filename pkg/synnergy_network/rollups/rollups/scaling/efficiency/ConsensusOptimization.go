package efficiency

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Block represents a basic block structure in the blockchain.
type Block struct {
	Index        int
	Timestamp    int64
	PreviousHash string
	Hash         string
	Data         string
	Nonce        int
}

// Blockchain represents a basic blockchain structure.
type Blockchain struct {
	mu      sync.Mutex
	blocks  []*Block
	workers int
}

// NewBlockchain initializes a new blockchain with a genesis block.
func NewBlockchain(workers int) *Blockchain {
	genesisBlock := &Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		PreviousHash: "",
		Hash:         calculateHash(0, time.Now().Unix(), "", "", 0),
		Data:         "Genesis Block",
		Nonce:        0,
	}
	return &Blockchain{
		blocks:  []*Block{genesisBlock},
		workers: workers,
	}
}

// AddBlock adds a new block to the blockchain.
func (bc *Blockchain) AddBlock(data string) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	previousBlock := bc.blocks[len(bc.blocks)-1]
	newBlock, err := bc.mineBlock(previousBlock, data)
	if err != nil {
		return err
	}

	bc.blocks = append(bc.blocks, newBlock)
	fmt.Printf("Block %d added to the blockchain.\n", newBlock.Index)
	return nil
}

// mineBlock mines a new block using a proof-of-work mechanism.
func (bc *Blockchain) mineBlock(previousBlock *Block, data string) (*Block, error) {
	index := previousBlock.Index + 1
	timestamp := time.Now().Unix()
	previousHash := previousBlock.Hash

	var nonce int
	var hash string
	var wg sync.WaitGroup
	found := false
	mu := &sync.Mutex{}

	wg.Add(bc.workers)
	for i := 0; i < bc.workers; i++ {
		go func(startNonce int) {
			defer wg.Done()
			for !found {
				select {
				case <-time.After(10 * time.Millisecond):
					if found {
						return
					}
					localNonce := startNonce
					localHash := calculateHash(index, timestamp, previousHash, data, localNonce)
					if isValidHash(localHash) {
						mu.Lock()
						if !found {
							nonce = localNonce
							hash = localHash
							found = true
						}
						mu.Unlock()
						return
					}
					startNonce += bc.workers
				}
			}
		}(i)
	}
	wg.Wait()

	if hash == "" {
		return nil, errors.New("failed to mine block")
	}

	return &Block{
		Index:        index,
		Timestamp:    timestamp,
		PreviousHash: previousHash,
		Hash:         hash,
		Data:         data,
		Nonce:        nonce,
	}, nil
}

// calculateHash calculates the hash of a block using the Argon2 algorithm.
func calculateHash(index int, timestamp int64, previousHash, data string, nonce int) string {
	input := fmt.Sprintf("%d%d%s%s%d", index, timestamp, previousHash, data, nonce)
	hash := argon2.IDKey([]byte(input), []byte("somesalt"), 1, 64*1024, 4, 32)
	return fmt.Sprintf("%x", hash)
}

// isValidHash checks if a hash meets the required difficulty.
func isValidHash(hash string) bool {
	return hash[:2] == "00"
}

// GetBlocks returns the current blocks in the blockchain.
func (bc *Blockchain) GetBlocks() []*Block {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return bc.blocks
}

// validateBlockchain validates the integrity of the blockchain.
func (bc *Blockchain) validateBlockchain() error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	for i := 1; i < len(bc.blocks); i++ {
		currentBlock := bc.blocks[i]
		previousBlock := bc.blocks[i-1]

		if currentBlock.Hash != calculateHash(currentBlock.Index, currentBlock.Timestamp, currentBlock.PreviousHash, currentBlock.Data, currentBlock.Nonce) {
			return errors.New("block hash is invalid")
		}
		if currentBlock.PreviousHash != previousBlock.Hash {
			return errors.New("blockchain integrity compromised")
		}
	}
	return nil
}

// optimizeConsensus implements an optimization to the consensus mechanism.
func (bc *Blockchain) optimizeConsensus() {
	// Placeholder for optimization logic
	// Implement consensus optimization logic such as reducing confirmation times, improving fault tolerance, etc.
	fmt.Println("Optimizing consensus mechanism...")
	// Example: Adjust mining difficulty based on network performance
}

func main() {
	// Initialize blockchain with 4 workers for mining
	bc := NewBlockchain(4)

	// Add blocks to the blockchain
	bc.AddBlock("First block data")
	bc.AddBlock("Second block data")

	// Validate the blockchain
	if err := bc.validateBlockchain(); err != nil {
		fmt.Printf("Blockchain validation failed: %v\n", err)
	} else {
		fmt.Println("Blockchain validation successful.")
	}

	// Optimize consensus mechanism
	bc.optimizeConsensus()
}
