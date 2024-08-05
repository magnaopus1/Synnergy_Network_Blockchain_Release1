package blockchain_pruning

import (
    "crypto/sha256"
    "encoding/hex"
    "sync"
    "time"
    "log"
)

// Block represents a basic block structure
type Block struct {
    Index        int
    Timestamp    string
    Data         string
    PrevHash     string
    Hash         string
}

// Blockchain represents a chain of blocks
type Blockchain struct {
    blocks []*Block
    mu     sync.Mutex
}

// NewBlock creates a new block using the provided data
func NewBlock(data string, prevHash string, index int) *Block {
    timestamp := time.Now().String()
    hash := calculateHash(index, timestamp, data, prevHash)
    return &Block{Index: index, Timestamp: timestamp, Data: data, PrevHash: prevHash, Hash: hash}
}

// calculateHash calculates the hash of a block
func calculateHash(index int, timestamp string, data string, prevHash string) string {
    record := string(index) + timestamp + data + prevHash
    h := sha256.New()
    h.Write([]byte(record))
    hashed := h.Sum(nil)
    return hex.EncodeToString(hashed)
}

// AddBlock adds a new block to the blockchain
func (bc *Blockchain) AddBlock(data string) {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    prevBlock := bc.blocks[len(bc.blocks)-1]
    newBlock := NewBlock(data, prevBlock.Hash, prevBlock.Index+1)
    bc.blocks = append(bc.blocks, newBlock)
}

// GenesisBlock creates the first block in the blockchain
func GenesisBlock() *Block {
    return NewBlock("Genesis Block", "", 0)
}

// NewBlockchain creates a new blockchain with the genesis block
func NewBlockchain() *Blockchain {
    return &Blockchain{blocks: []*Block{GenesisBlock()}}
}

// Prune removes blocks older than a certain timestamp while preserving blockchain integrity
func (bc *Blockchain) Prune(retentionPeriod time.Duration) {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    currentTime := time.Now()
    prunedBlocks := []*Block{}

    for _, block := range bc.blocks {
        blockTime, _ := time.Parse(time.RFC3339, block.Timestamp)
        if currentTime.Sub(blockTime) <= retentionPeriod {
            prunedBlocks = append(prunedBlocks, block)
        }
    }

    bc.blocks = prunedBlocks
}

// Snapshot creates a snapshot of the current blockchain state
func (bc *Blockchain) Snapshot() []*Block {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    snapshot := make([]*Block, len(bc.blocks))
    copy(snapshot, bc.blocks)
    return snapshot
}

// Validate ensures that the blockchain is valid after pruning
func (bc *Blockchain) Validate() bool {
    bc.mu.Lock()
    defer bc.mu.Unlock()

    for i := 1; i < len(bc.blocks); i++ {
        prevBlock := bc.blocks[i-1]
        currBlock := bc.blocks[i]

        if currBlock.PrevHash != prevBlock.Hash || currBlock.Hash != calculateHash(currBlock.Index, currBlock.Timestamp, currBlock.Data, currBlock.PrevHash) {
            log.Printf("Validation failed at block %d", currBlock.Index)
            return false
        }
    }

    return true
}
