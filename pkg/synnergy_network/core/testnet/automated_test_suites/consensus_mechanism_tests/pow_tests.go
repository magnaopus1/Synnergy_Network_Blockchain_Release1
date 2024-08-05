package consensus_mechanism_tests

import (
    "crypto/sha256"
    "fmt"
    "time"
    "math/big"
    "github.com/synnergy_network/core/consensus"
    "github.com/synnergy_network/core/cryptography"
    "github.com/synnergy_network/core/util"
    "github.com/synnergy_network/core/blockchain"
)

// TestPoW represents the structure for Proof of Work testing
type TestPoW struct {
    difficulty      *big.Int
    targetTime      time.Duration
    maxIterations   int64
}

// NewTestPoW creates a new TestPoW instance with specified difficulty and target time
func NewTestPoW(difficulty *big.Int, targetTime time.Duration, maxIterations int64) *TestPoW {
    return &TestPoW{
        difficulty: difficulty,
        targetTime: targetTime,
        maxIterations: maxIterations,
    }
}

// Run executes the Proof of Work test
func (t *TestPoW) Run() error {
    fmt.Println("Starting Proof of Work test...")

    // Initialize blockchain for testing
    bc := blockchain.NewBlockchain()
    genesisBlock := blockchain.NewBlock(0, "0", time.Now().Unix(), []byte{}, t.difficulty)
    bc.AddBlock(genesisBlock)

    // Create a new block
    prevBlock := bc.GetLatestBlock()
    newBlock := blockchain.NewBlock(prevBlock.Index+1, prevBlock.Hash, time.Now().Unix(), []byte("Test Data"), t.difficulty)

    // Start mining
    startTime := time.Now()
    nonce, hash := t.mine(newBlock, t.maxIterations)
    elapsedTime := time.Since(startTime)

    if elapsedTime > t.targetTime {
        return fmt.Errorf("PoW test failed: mining took too long (%s)", elapsedTime)
    }

    // Verify mined block
    newBlock.Hash = hash
    newBlock.Nonce = nonce
    if !t.verifyBlock(newBlock) {
        return fmt.Errorf("PoW test failed: block verification failed")
    }

    fmt.Printf("PoW test passed: mined block in %s with nonce %d\n", elapsedTime, nonce)
    return nil
}

// mine performs the mining process to find a valid hash
func (t *TestPoW) mine(block *blockchain.Block, maxIterations int64) (int64, string) {
    var nonce int64
    var hash string
    for nonce = 0; nonce < maxIterations; nonce++ {
        hash = t.calculateHash(block, nonce)
        if t.isHashValid(hash) {
            return nonce, hash
        }
    }
    return nonce, hash
}

// calculateHash calculates the hash for a block with a given nonce
func (t *TestPoW) calculateHash(block *blockchain.Block, nonce int64) string {
    record := fmt.Sprintf("%d%s%d%s%d", block.Index, block.PreviousHash, block.Timestamp, block.Data, nonce)
    h := sha256.New()
    h.Write([]byte(record))
    return fmt.Sprintf("%x", h.Sum(nil))
}

// isHashValid checks if the hash meets the difficulty requirements
func (t *TestPoW) isHashValid(hash string) bool {
    hashInt := new(big.Int)
    hashInt.SetString(hash, 16)
    return hashInt.Cmp(t.difficulty) == -1
}

// verifyBlock verifies the integrity and correctness of a mined block
func (t *TestPoW) verifyBlock(block *blockchain.Block) bool {
    calculatedHash := t.calculateHash(block, block.Nonce)
    return calculatedHash == block.Hash && t.isHashValid(block.Hash)
}

// Example usage of PoW testing (not included in the final production file)
// func main() {
//     difficulty := big.NewInt(1)
//     difficulty.Lsh(difficulty, 255) // Equivalent to setting difficulty to 2^255
//     test := NewTestPoW(difficulty, 5*time.Second, 1000000)
//     if err := test.Run(); err != nil {
//         fmt.Println(err)
//     }
// }
