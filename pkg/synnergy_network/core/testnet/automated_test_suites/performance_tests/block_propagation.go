package performance_tests

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "log"
    "math/big"
    "time"
    "sync"
)

// Block represents a simple block in the blockchain.
type Block struct {
    Index     int
    Timestamp int64
    Data      string
    PrevHash  string
    Hash      string
}

// Blockchain represents a simple chain of blocks.
type Blockchain struct {
    blocks []Block
    mu     sync.Mutex
}

// NewBlock creates a new block.
func NewBlock(index int, timestamp int64, data string, prevHash string) Block {
    block := Block{Index: index, Timestamp: timestamp, Data: data, PrevHash: prevHash}
    block.Hash = calculateHash(block)
    return block
}

// calculateHash generates a SHA-256 hash for a block.
func calculateHash(block Block) string {
    record := string(block.Index) + string(block.Timestamp) + block.Data + block.PrevHash
    h := sha256.New()
    h.Write([]byte(record))
    hashed := h.Sum(nil)
    return hex.EncodeToString(hashed)
}

// AddBlock adds a new block to the blockchain.
func (bc *Blockchain) AddBlock(data string) {
    bc.mu.Lock()
    defer bc.mu.Unlock()
    prevBlock := bc.blocks[len(bc.blocks)-1]
    newBlock := NewBlock(prevBlock.Index+1, time.Now().Unix(), data, prevBlock.Hash)
    bc.blocks = append(bc.blocks, newBlock)
}

// GetBlocks returns all blocks in the blockchain.
func (bc *Blockchain) GetBlocks() []Block {
    bc.mu.Lock()
    defer bc.mu.Unlock()
    return bc.blocks
}

// InitializeBlockchain initializes a new blockchain with a genesis block.
func InitializeBlockchain() *Blockchain {
    genesisBlock := NewBlock(0, time.Now().Unix(), "Genesis Block", "")
    return &Blockchain{blocks: []Block{genesisBlock}}
}

// SimulateBlockPropagation simulates the propagation of blocks in the network.
func SimulateBlockPropagation(numBlocks int, delay time.Duration) {
    blockchain := InitializeBlockchain()
    for i := 0; i < numBlocks; i++ {
        time.Sleep(delay)
        data := generateRandomData()
        blockchain.AddBlock(data)
        log.Printf("Block %d added: %s", i+1, data)
    }
    log.Println("Block propagation simulation completed.")
}

// generateRandomData generates random data for a block.
func generateRandomData() string {
    n, err := rand.Int(rand.Reader, big.NewInt(1000000))
    if err != nil {
        log.Fatalf("Failed to generate random data: %v", err)
    }
    return n.String()
}

// MonitorBlockPropagation monitors and logs the propagation of blocks.
func MonitorBlockPropagation(blockchain *Blockchain) {
    for {
        time.Sleep(10 * time.Second)
        blocks := blockchain.GetBlocks()
        log.Printf("Total blocks: %d", len(blocks))
        for _, block := range blocks {
            log.Printf("Block %d: %s", block.Index, block.Hash)
        }
    }
}

// RunBlockPropagationTest runs the block propagation test.
func RunBlockPropagationTest(numBlocks int, delay time.Duration) {
    go SimulateBlockPropagation(numBlocks, delay)
    blockchain := InitializeBlockchain()
    go MonitorBlockPropagation(blockchain)
}

func main() {
    // Run the block propagation test with desired parameters.
    RunBlockPropagationTest(10, 1*time.Second)
}
